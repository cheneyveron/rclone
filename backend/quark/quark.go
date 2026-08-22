// Package quark provides an upload-only interface to the Quark Drive open platform.
package quark

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rclone/rclone/backend/quark/api"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/config/obscure"
	"github.com/rclone/rclone/fs/fserrors"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/dircache"
	"github.com/rclone/rclone/lib/encoder"
	"github.com/rclone/rclone/lib/pacer"
	"github.com/rclone/rclone/lib/random"
)

const (
	defaultAPIURL   = "https://open-api-drive.quark.cn"
	defaultClientID = "third_party_agent"
	defaultSignKey  = "cf134812e2de4032bd1cb7c3727e84b3"
	defaultDeviceID = "wild_claw"
	defaultPartSize = int64(10 * fs.Mebi)
	formUploadLimit = int64(10 * fs.Mebi)
)

var retryErrorCodes = []int{
	http.StatusRequestTimeout,
	http.StatusConflict,
	http.StatusTooManyRequests,
	http.StatusInternalServerError,
	http.StatusBadGateway,
	http.StatusServiceUnavailable,
	http.StatusGatewayTimeout,
	509,
}

// Options defines the configuration for this backend.
type Options struct {
	AccessToken  string               `config:"access_token"`
	RefreshToken string               `config:"refresh_token"`
	UserID       string               `config:"user_id"`
	DeviceID     string               `config:"device_id"`
	Platform     string               `config:"platform"`
	RootFolderID string               `config:"root_folder_id"`
	ClientID     string               `config:"client_id"`
	SignKey      string               `config:"sign_key"`
	Enc          encoder.MultiEncoder `config:"encoding"`
}

// Fs represents an upload-only Quark Drive remote.
type Fs struct {
	name         string
	root         string
	opt          Options
	features     *fs.Features
	client       *http.Client
	pacer        *fs.Pacer
	dirCache     *dircache.DirCache
	config       configmap.Mapper
	apiURL       string
	tokenMu      sync.RWMutex
	refreshMu    sync.Mutex
	accessToken  string
	refreshToken string
}

// Object describes a file uploaded during the current rclone process.
type Object struct {
	fs       *Fs
	remote   string
	id       string
	parentID string
	size     int64
	modTime  time.Time
	mimeType string
}

type proofFields struct {
	ProofVersion string `json:"proof_version,omitempty"`
	ProofSeed1   string `json:"proof_seed1,omitempty"`
	ProofSeed2   string `json:"proof_seed2,omitempty"`
	ProofCode1   string `json:"proof_code1,omitempty"`
	ProofCode2   string `json:"proof_code2,omitempty"`
}

type uploadPreRequest struct {
	FileName          string     `json:"file_name"`
	Size              int64      `json:"size"`
	SHA1              string     `json:"sha1"`
	MD5               string     `json:"md5,omitempty"`
	ParentID          string     `json:"pdir_fid,omitempty"`
	FormatType        string     `json:"format_type"`
	CreatedAt         int64      `json:"l_created_at"`
	UpdatedAt         int64      `json:"l_updated_at"`
	SamePathFileReuse bool       `json:"same_path_file_reuse"`
	ParallelUpload    bool       `json:"parallel_upload"`
	HashUpdate        bool       `json:"hash_update"`
	DeviceID          string     `json:"device_id,omitempty"`
	PartInfo          []partInfo `json:"part_info_list,omitempty"`
	proofFields
}

type parallelSHA1Context struct {
	PartOffset int64     `json:"part_offset"`
	H          [5]uint32 `json:"h"`
}

type partInfo struct {
	PartNumber int                  `json:"part_number"`
	PartSize   int64                `json:"part_size"`
	SHA1       *parallelSHA1Context `json:"parallel_sha1_ctx,omitempty"`
}

type uploadURLsRequest struct {
	TaskID   string     `json:"task_id"`
	PartInfo []partInfo `json:"part_info_list"`
}

type uploadedPart struct {
	PartNumber int    `json:"part_number"`
	ETag       string `json:"etag"`
}

type uploadFinishRequest struct {
	TaskID   string         `json:"task_id"`
	PartInfo []uploadedPart `json:"part_info_list"`
}

func init() {
	fs.Register(&fs.RegInfo{
		Name:        "quark",
		Description: "Quark Drive open platform (upload-only)",
		NewFs:       NewFs,
		Options: []fs.Option{{
			Name:       "access_token",
			Help:       "Long-lived access token issued by the Quark Drive open platform.",
			Required:   true,
			Sensitive:  true,
			IsPassword: true,
		}, {
			Name:       "refresh_token",
			Help:       "Refresh token used to renew an expired access token.",
			Sensitive:  true,
			IsPassword: true,
		}, {
			Name:      "user_id",
			Help:      "Quark Drive user ID used to generate upload proof codes.",
			Required:  true,
			Sensitive: true,
		}, {
			Name:      "device_id",
			Help:      "Device ID associated with the open-platform authorization.",
			Default:   defaultDeviceID,
			Advanced:  true,
			Sensitive: true,
		}, {
			Name:     "platform",
			Help:     "Device platform sent to the open platform.",
			Advanced: true,
		}, {
			Name: "root_folder_id",
			Help: `FID below which backup directories are created.

Leave blank to use the platform default directory. Set this to 0 only when
backups should explicitly be written below the drive root.`,
			Advanced:  true,
			Sensitive: true,
		}, {
			Name:     "client_id",
			Help:     "Open-platform client ID.",
			Default:  defaultClientID,
			Advanced: true,
		}, {
			Name:      "sign_key",
			Help:      "Open-platform request signing key.",
			Default:   defaultSignKey,
			Advanced:  true,
			Sensitive: true,
		}, {
			Name:     config.ConfigEncoding,
			Help:     config.ConfigEncodingHelp,
			Advanced: true,
			Default: (encoder.Display |
				encoder.EncodeBackSlash |
				encoder.EncodeLeftSpace |
				encoder.EncodeLeftTilde |
				encoder.EncodeRightPeriod |
				encoder.EncodeRightSpace |
				encoder.EncodeWin |
				encoder.EncodeInvalidUtf8),
		}},
	})
}

// NewFs constructs an upload-only Fs.
func NewFs(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
	opt := new(Options)
	if err := configstruct.Set(m, opt); err != nil {
		return nil, err
	}
	accessToken, err := obscure.Reveal(opt.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to reveal Quark Drive access token: %w", err)
	}
	refreshToken := ""
	if opt.RefreshToken != "" {
		refreshToken, err = obscure.Reveal(opt.RefreshToken)
		if err != nil {
			return nil, fmt.Errorf("failed to reveal Quark Drive refresh token: %w", err)
		}
	}
	if accessToken == "" {
		return nil, errors.New("quark drive access_token is required")
	}
	if opt.UserID == "" {
		return nil, errors.New("quark drive user_id is required")
	}
	if opt.ClientID == "" || opt.SignKey == "" {
		return nil, errors.New("quark drive client_id and sign_key are required")
	}
	root = strings.Trim(root, "/")
	f := &Fs{
		name:         name,
		root:         root,
		opt:          *opt,
		client:       fshttp.NewClient(ctx),
		pacer:        fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(100*time.Millisecond), pacer.MaxSleep(2*time.Second), pacer.DecayConstant(2))),
		config:       m,
		apiURL:       defaultAPIURL,
		accessToken:  accessToken,
		refreshToken: refreshToken,
	}
	f.features = (&fs.Features{CanHaveEmptyDirectories: true, ReadMimeType: true}).Fill(ctx, f)
	f.dirCache = dircache.New(root, opt.RootFolderID, f)
	return f, nil
}

// Name returns the configured remote name.
func (f *Fs) Name() string { return f.name }

// Root returns the configured remote path.
func (f *Fs) Root() string { return f.root }

// String returns a description of the remote.
func (f *Fs) String() string { return fmt.Sprintf("Quark Drive upload-only root %q", f.root) }

// Precision returns the timestamp precision accepted for new uploads.
func (f *Fs) Precision() time.Duration { return time.Millisecond }

// Hashes reports that uploaded objects do not expose persistent hashes.
func (f *Fs) Hashes() hash.Set { return hash.Set(hash.None) }

// Features returns optional backend capabilities.
func (f *Fs) Features() *fs.Features { return f.features }

// List reports the open-platform directory-listing limitation.
func (f *Fs) List(ctx context.Context, dir string) (fs.DirEntries, error) {
	return nil, fmt.Errorf("Quark Drive open platform cannot list directories; use copy --no-traverse with a unique destination: %w", fs.ErrorNotImplemented)
}

// NewObject reports objects as absent because the open platform cannot resolve paths.
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	return nil, fs.ErrorObjectNotFound
}

// FindLeaf reports a cache miss; CreateDir is idempotent and resolves it when writing.
func (f *Fs) FindLeaf(ctx context.Context, parentID, leaf string) (string, bool, error) {
	return "", false, nil
}

// CreateDir creates or resolves a directory through the idempotent open-platform API.
func (f *Fs) CreateDir(ctx context.Context, parentID, leaf string) (string, error) {
	request := map[string]string{"dir_path": f.opt.Enc.FromStandardName(leaf)}
	if parentID != "" {
		request["pdir_fid"] = parentID
	}
	var response api.CreateDirResponse
	if err := f.callJSON(ctx, http.MethodPost, "/open/v1/dir", request, &response); err != nil {
		return "", err
	}
	if response.Data.FID == "" {
		return "", errors.New("quark drive create directory returned no FID")
	}
	return response.Data.FID, nil
}

// Mkdir creates the directory and any missing parents.
func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	_, err := f.dirCache.FindDir(ctx, dir, true)
	return err
}

// Rmdir reports the open-platform deletion limitation.
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	return fmt.Errorf("Quark Drive open platform cannot remove directories: %w", fs.ErrorNotImplemented)
}

func (f *Fs) token() (accessToken, refreshToken string) {
	f.tokenMu.RLock()
	defer f.tokenMu.RUnlock()
	return f.accessToken, f.refreshToken
}

func (f *Fs) setTokens(accessToken, refreshToken string) {
	f.tokenMu.Lock()
	defer f.tokenMu.Unlock()
	f.accessToken = accessToken
	if refreshToken != "" {
		f.refreshToken = refreshToken
	}
	f.config.Set("access_token", obscure.MustObscure(f.accessToken))
	if f.refreshToken != "" {
		f.config.Set("refresh_token", obscure.MustObscure(f.refreshToken))
	}
}

func (f *Fs) signedHeaders(method, requestPath string) http.Header {
	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	plain := strings.ToUpper(method) + "&" + requestPath + "&" + timestamp + "&" + f.opt.SignKey
	sum := sha256.Sum256([]byte(plain))
	header := make(http.Header)
	header.Set("x-pan-client-id", f.opt.ClientID)
	header.Set("x-pan-tm", timestamp)
	header.Set("x-pan-token", hex.EncodeToString(sum[:]))
	header.Set("Content-Type", "application/json")
	header.Set("Accept", "application/json")
	return header
}

func (f *Fs) requestURL(requestPath, accessToken string) (string, error) {
	u, err := url.Parse(f.apiURL + requestPath)
	if err != nil {
		return "", err
	}
	query := u.Query()
	query.Set("req_id", random.String(32))
	query.Set("access_token", accessToken)
	if f.opt.DeviceID != "" {
		query.Set("device_id", f.opt.DeviceID)
	}
	if f.opt.Platform != "" {
		query.Set("platform", f.opt.Platform)
	}
	u.RawQuery = query.Encode()
	return u.String(), nil
}

type requestPreparer func(http.Header) (any, error)

func fixedRequest(in any) requestPreparer {
	return func(http.Header) (any, error) { return in, nil }
}

func (f *Fs) callJSON(ctx context.Context, method, requestPath string, in, out any) error {
	return f.callJSONPrepared(ctx, method, requestPath, fixedRequest(in), out)
}

func (f *Fs) callJSONPrepared(ctx context.Context, method, requestPath string, prepare requestPreparer, out any) error {
	for authAttempt := 0; authAttempt < 2; authAttempt++ {
		accessToken, refreshToken := f.token()
		headers := f.signedHeaders(method, requestPath)
		in, err := prepare(headers)
		if err != nil {
			return err
		}
		payload, err := json.Marshal(in)
		if err != nil {
			return err
		}
		rawURL, err := f.requestURL(requestPath, accessToken)
		if err != nil {
			return err
		}
		var responseBody []byte
		var statusCode int
		err = f.pacer.Call(func() (bool, error) {
			req, requestErr := http.NewRequestWithContext(ctx, method, rawURL, bytes.NewReader(payload))
			if requestErr != nil {
				return false, requestErr
			}
			req.Header = headers.Clone()
			resp, requestErr := f.client.Do(req)
			if requestErr != nil {
				return fserrors.ShouldRetry(requestErr), requestErr
			}
			defer resp.Body.Close()
			responseBody, requestErr = io.ReadAll(io.LimitReader(resp.Body, 4*int64(fs.Mebi)))
			statusCode = resp.StatusCode
			if requestErr != nil {
				return true, requestErr
			}
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				return fserrors.ShouldRetryHTTP(resp, retryErrorCodes), nil
			}
			return false, nil
		})
		if err != nil {
			return err
		}
		var common api.Response
		if err = json.Unmarshal(responseBody, &common); err != nil {
			return fmt.Errorf("failed to decode Quark Drive response (HTTP %d): %w", statusCode, err)
		}
		if common.Errno == 11001 && authAttempt == 0 && refreshToken != "" {
			if err = f.refreshAccessToken(ctx, accessToken); err != nil {
				return err
			}
			continue
		}
		if err = common.Check(); err != nil {
			return err
		}
		if statusCode < 200 || statusCode >= 300 {
			return fmt.Errorf("Quark Drive returned HTTP status %d", statusCode)
		}
		if out != nil {
			if err = json.Unmarshal(responseBody, out); err != nil {
				return err
			}
		}
		return nil
	}
	return errors.New("quark drive authentication retry exhausted")
}

func (f *Fs) refreshAccessToken(ctx context.Context, staleAccessToken string) error {
	f.refreshMu.Lock()
	defer f.refreshMu.Unlock()
	accessToken, refreshToken := f.token()
	if accessToken != staleAccessToken {
		return nil
	}
	if refreshToken == "" {
		return errors.New("quark drive access token expired and no refresh_token is configured")
	}
	requestPath := "/agent/v1/oauth/access_token/rotate"
	headers := f.signedHeaders(http.MethodPost, requestPath)
	payload, err := json.Marshal(map[string]string{"refresh_token": refreshToken, "device_id": f.opt.DeviceID})
	if err != nil {
		return err
	}
	u, err := url.Parse(f.apiURL + requestPath)
	if err != nil {
		return err
	}
	query := u.Query()
	query.Set("req_id", random.String(32))
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header = headers
	resp, err := f.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("failed to refresh Quark Drive token: HTTP %s", resp.Status)
	}
	var response api.RotateTokenResponse
	if err = json.NewDecoder(io.LimitReader(resp.Body, int64(fs.Mebi))).Decode(&response); err != nil {
		return err
	}
	if err = response.Response.Check(); err != nil {
		return fmt.Errorf("failed to refresh Quark Drive token: %w", err)
	}
	if response.Data.AccessToken == "" {
		return errors.New("quark drive token refresh returned no access token")
	}
	f.setTokens(response.Data.AccessToken, response.Data.RefreshToken)
	return nil
}

func doubleMD5(value string) string {
	first := md5.Sum([]byte(value))
	second := md5.Sum([]byte(hex.EncodeToString(first[:])))
	return hex.EncodeToString(second[:])
}

func proofCode(file *os.File, size int64, seed string) (string, error) {
	if size == 0 {
		return "", nil
	}
	prefix, err := strconv.ParseUint(seed[:16], 16, 64)
	if err != nil {
		return "", err
	}
	start := int64(prefix % uint64(size))
	length := min(int64(8), size-start)
	data := make([]byte, length)
	if _, err = file.ReadAt(data, start); err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func makeProofFields(file *os.File, size int64, userID, panToken string) (proofFields, error) {
	seed1 := doubleMD5(userID + panToken)
	seed2 := doubleMD5(strconv.FormatInt(size, 10))
	code1, err := proofCode(file, size, seed1)
	if err != nil {
		return proofFields{}, err
	}
	code2, err := proofCode(file, size, seed2)
	if err != nil {
		return proofFields{}, err
	}
	return proofFields{ProofVersion: "v1", ProofSeed1: seed1, ProofSeed2: seed2, ProofCode1: code1, ProofCode2: code2}, nil
}

func spoolInput(in io.Reader, expectedSize int64) (file *os.File, size int64, md5sum, sha1sum string, cleanup func(), err error) {
	file, err = os.CreateTemp("", "rclone-quark-upload-")
	if err != nil {
		return nil, 0, "", "", func() {}, err
	}
	cleanup = func() {
		_ = file.Close()
		_ = os.Remove(file.Name())
	}
	md5Hasher, sha1Hasher := md5.New(), sha1.New()
	size, err = io.Copy(io.MultiWriter(file, md5Hasher, sha1Hasher), in)
	if err != nil {
		cleanup()
		return nil, 0, "", "", func() {}, err
	}
	if expectedSize >= 0 && size != expectedSize {
		cleanup()
		return nil, 0, "", "", func() {}, fmt.Errorf("source size changed during upload: expected=%d actual=%d", expectedSize, size)
	}
	return file, size, hex.EncodeToString(md5Hasher.Sum(nil)), hex.EncodeToString(sha1Hasher.Sum(nil)), cleanup, nil
}

func sha1Context(hasher encoding.BinaryMarshaler, offset int64) (*parallelSHA1Context, error) {
	state, err := sha1State(hasher)
	if err != nil {
		return nil, err
	}
	state.PartOffset = offset
	return state, nil
}

func sha1State(hasher encoding.BinaryMarshaler) (*parallelSHA1Context, error) {
	state, err := hasher.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if len(state) < 24 || string(state[:4]) != "sha\x01" {
		return nil, errors.New("unexpected SHA1 state encoding")
	}
	result := new(parallelSHA1Context)
	for i := range result.H {
		result.H[i] = binary.BigEndian.Uint32(state[4+i*4:])
	}
	return result, nil
}

func formSHA1State(file *os.File, size int64) (*parallelSHA1Context, error) {
	hasher := sha1.New()
	if _, err := io.Copy(hasher, io.NewSectionReader(file, 0, size)); err != nil {
		return nil, err
	}
	marshaler, ok := hasher.(encoding.BinaryMarshaler)
	if !ok {
		return nil, errors.New("SHA1 implementation cannot export upload state")
	}
	return sha1State(marshaler)
}

func resolvePartSize(serverPartSize int64) int64 {
	partSize := serverPartSize
	if partSize <= 0 {
		partSize = defaultPartSize
	}
	return partSize
}

func findUploadURL(urls []api.UploadURL, partNumber int) (*api.UploadURL, error) {
	for i := range urls {
		if urls[i].PartNumber == partNumber || len(urls) == 1 {
			return &urls[i], nil
		}
	}
	return nil, fmt.Errorf("quark drive returned no upload URL for part %d", partNumber)
}

func (f *Fs) putPart(ctx context.Context, uploadURL *api.UploadURL, commonHeaders map[string]string, data []byte) (string, error) {
	var etag string
	var status string
	var responseBody []byte
	err := f.pacer.Call(func() (bool, error) {
		req, requestErr := http.NewRequestWithContext(ctx, http.MethodPut, uploadURL.UploadURL, bytes.NewReader(data))
		if requestErr != nil {
			return false, requestErr
		}
		req.ContentLength = int64(len(data))
		for key, value := range commonHeaders {
			req.Header.Set(key, value)
		}
		if uploadURL.SignatureInfo.Signature != "" {
			req.Header.Set("Authorization", uploadURL.SignatureInfo.Signature)
		}
		resp, requestErr := f.client.Do(req)
		if requestErr != nil {
			return fserrors.ShouldRetry(requestErr), requestErr
		}
		defer resp.Body.Close()
		status = resp.Status
		responseBody, requestErr = io.ReadAll(io.LimitReader(resp.Body, int64(fs.Mebi)))
		if requestErr != nil {
			return true, requestErr
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fserrors.ShouldRetryHTTP(resp, retryErrorCodes), nil
		}
		etag = resp.Header.Get("ETag")
		return false, nil
	})
	if err != nil {
		return "", err
	}
	if etag == "" && status != "" && !strings.HasPrefix(status, "2") {
		return "", fmt.Errorf("quark drive part upload returned HTTP %s: %s", status, strings.TrimSpace(string(responseBody)))
	}
	if etag == "" {
		return "", errors.New("quark drive part upload returned no ETag")
	}
	return etag, nil
}

func (f *Fs) upload(ctx context.Context, in io.Reader, src fs.ObjectInfo, leaf, parentID string) (*Object, error) {
	file, size, md5sum, sha1sum, cleanup, err := spoolInput(in, src.Size())
	if err != nil {
		return nil, err
	}
	defer cleanup()
	mimeType := fs.MimeType(ctx, src)
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	modTime := src.ModTime(ctx)
	if modTime.IsZero() {
		modTime = time.Now()
	}
	modTime = time.UnixMilli(modTime.UnixMilli())
	formUpload := size <= formUploadLimit
	var formPartInfo []partInfo
	if formUpload {
		state, stateErr := formSHA1State(file, size)
		if stateErr != nil {
			return nil, stateErr
		}
		formPartInfo = []partInfo{{PartNumber: 1, PartSize: size, SHA1: state}}
	}
	var pre api.UploadPreResponse
	err = f.callJSONPrepared(ctx, http.MethodPost, "/open/v1/file/upload_pre", func(headers http.Header) (any, error) {
		proof, proofErr := makeProofFields(file, size, f.opt.UserID, headers.Get("x-pan-token"))
		if proofErr != nil {
			return nil, proofErr
		}
		request := uploadPreRequest{
			FileName:          f.opt.Enc.FromStandardName(leaf),
			Size:              size,
			ParentID:          parentID,
			FormatType:        mimeType,
			CreatedAt:         modTime.UnixMilli(),
			UpdatedAt:         modTime.UnixMilli(),
			SamePathFileReuse: false,
			ParallelUpload:    true,
			HashUpdate:        !formUpload,
			DeviceID:          f.opt.DeviceID,
			PartInfo:          formPartInfo,
			proofFields:       proof,
		}
		if formUpload {
			request.SHA1 = sha1sum
			request.MD5 = md5sum
		}
		return request, nil
	}, &pre)
	if err != nil {
		return nil, err
	}
	if pre.Data.Finish && pre.Data.FID != "" {
		return &Object{fs: f, remote: src.Remote(), id: pre.Data.FID, parentID: parentID, size: size, modTime: modTime, mimeType: mimeType}, nil
	}
	if pre.Data.TaskID == "" {
		return nil, errors.New("quark drive upload_pre returned no task ID")
	}
	if formUpload {
		uploadURL, urlErr := findUploadURL(pre.Data.UploadURLs, 1)
		if urlErr != nil {
			return nil, urlErr
		}
		chunk, readErr := io.ReadAll(io.NewSectionReader(file, 0, size))
		if readErr != nil {
			return nil, readErr
		}
		etag, uploadErr := f.putPart(ctx, uploadURL, pre.Data.CommonHeaders, chunk)
		if uploadErr != nil {
			return nil, uploadErr
		}
		var finish api.UploadFinishResponse
		finishRequest := uploadFinishRequest{TaskID: pre.Data.TaskID, PartInfo: []uploadedPart{{PartNumber: 1, ETag: etag}}}
		if err = f.callJSON(ctx, http.MethodPost, "/open/v1/file/upload_finish", finishRequest, &finish); err != nil {
			return nil, err
		}
		if !finish.Data.Finish || finish.Data.FID == "" {
			return nil, errors.New("quark drive upload_finish did not finish the upload")
		}
		return &Object{fs: f, remote: src.Remote(), id: finish.Data.FID, parentID: parentID, size: size, modTime: modTime, mimeType: mimeType}, nil
	}
	partSize := resolvePartSize(pre.Data.PartSize)
	partCount := int((size + partSize - 1) / partSize)
	if partCount == 0 {
		partCount = 1
	}
	parts := make([]uploadedPart, 0, partCount)
	sha1Hasher := sha1.New()
	marshaler, ok := sha1Hasher.(encoding.BinaryMarshaler)
	if !ok {
		return nil, errors.New("SHA1 implementation cannot export multipart state")
	}
	for partNumber := 1; partNumber <= partCount; partNumber++ {
		offset := int64(partNumber-1) * partSize
		length := min(partSize, max(int64(0), size-offset))
		var state *parallelSHA1Context
		if offset > 0 {
			state, err = sha1Context(marshaler, offset)
			if err != nil {
				return nil, err
			}
		}
		chunk, readErr := io.ReadAll(io.NewSectionReader(file, offset, length))
		if readErr != nil {
			return nil, readErr
		}
		var urls api.UploadURLsResponse
		request := uploadURLsRequest{TaskID: pre.Data.TaskID, PartInfo: []partInfo{{PartNumber: partNumber, PartSize: length, SHA1: state}}}
		if err = f.callJSON(ctx, http.MethodPost, "/open/v1/file/get_upload_urls", request, &urls); err != nil {
			return nil, err
		}
		uploadURL, urlErr := findUploadURL(urls.Data.UploadURLs, partNumber)
		if urlErr != nil {
			return nil, urlErr
		}
		commonHeaders := urls.Data.CommonHeaders
		if len(commonHeaders) == 0 {
			commonHeaders = pre.Data.CommonHeaders
		}
		etag, uploadErr := f.putPart(ctx, uploadURL, commonHeaders, chunk)
		if uploadErr != nil {
			return nil, uploadErr
		}
		if _, err = sha1Hasher.Write(chunk); err != nil {
			return nil, err
		}
		parts = append(parts, uploadedPart{PartNumber: partNumber, ETag: etag})
	}
	var hashResponse api.UploadHashResponse
	if err = f.callJSON(ctx, http.MethodPost, "/open/v1/file/update/hash", map[string]string{"task_id": pre.Data.TaskID, "sha1": sha1sum, "md5": md5sum}, &hashResponse); err != nil {
		return nil, err
	}
	id := hashResponse.Data.FID
	if !hashResponse.Data.Finish {
		var finish api.UploadFinishResponse
		if err = f.callJSON(ctx, http.MethodPost, "/open/v1/file/upload_finish", uploadFinishRequest{TaskID: pre.Data.TaskID, PartInfo: parts}, &finish); err != nil {
			return nil, err
		}
		if !finish.Data.Finish {
			return nil, errors.New("quark drive upload_finish did not finish the upload")
		}
		id = finish.Data.FID
	}
	if id == "" {
		return nil, errors.New("quark drive upload returned no FID")
	}
	return &Object{fs: f, remote: src.Remote(), id: id, parentID: parentID, size: size, modTime: modTime, mimeType: mimeType}, nil
}

// Put uploads a new object without probing the destination.
func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	leaf, parentID, err := f.dirCache.FindPath(ctx, src.Remote(), true)
	if err != nil {
		return nil, err
	}
	return f.upload(ctx, in, src, leaf, parentID)
}

// PutStream uploads an object whose size is not known in advance.
func (f *Fs) PutStream(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	return f.Put(ctx, in, src, options...)
}

// String returns the remote path.
func (o *Object) String() string {
	if o == nil {
		return "<nil>"
	}
	return o.remote
}

// Fs returns the parent filesystem.
func (o *Object) Fs() fs.Info { return o.fs }

// Remote returns the object path relative to the remote root.
func (o *Object) Remote() string { return o.remote }

// ModTime returns the upload modification time.
func (o *Object) ModTime(ctx context.Context) time.Time { return o.modTime }

// Size returns the uploaded size.
func (o *Object) Size() int64 { return o.size }

// Storable reports that this is a regular object.
func (o *Object) Storable() bool { return true }

// ID returns the FID assigned by Quark Drive.
func (o *Object) ID() string { return o.id }

// ParentID returns the parent directory FID.
func (o *Object) ParentID() string { return o.parentID }

// MimeType returns the media type used for upload.
func (o *Object) MimeType(ctx context.Context) string { return o.mimeType }

// Hash reports that the open platform does not expose a persistent hash here.
func (o *Object) Hash(ctx context.Context, hashType hash.Type) (string, error) {
	return "", hash.ErrUnsupported
}

// SetModTime reports that existing objects cannot be changed by this backend.
func (o *Object) SetModTime(ctx context.Context, modTime time.Time) error {
	return fs.ErrorCantSetModTimeWithoutDelete
}

// Open reports that this upload-only backend does not implement restore.
func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (io.ReadCloser, error) {
	return nil, fmt.Errorf("Quark Drive open-platform backup backend does not implement reads: %w", fs.ErrorNotImplemented)
}

// Update writes another upload to the same logical path.
func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	newObject, err := o.fs.upload(ctx, in, src, path.Base(o.remote), o.parentID)
	if err != nil {
		return err
	}
	*o = *newObject
	return nil
}

// Remove reports the open-platform deletion limitation.
func (o *Object) Remove(ctx context.Context) error {
	return fmt.Errorf("Quark Drive open platform cannot delete files: %w", fs.ErrorNotImplemented)
}

var (
	_ fs.Fs              = (*Fs)(nil)
	_ fs.PutStreamer     = (*Fs)(nil)
	_ fs.DirCacheFlusher = (*Fs)(nil)
	_ fs.Object          = (*Object)(nil)
	_ fs.IDer            = (*Object)(nil)
	_ fs.ParentIDer      = (*Object)(nil)
	_ fs.MimeTyper       = (*Object)(nil)
)

// DirCacheFlush resets IDs learned during the current process.
func (f *Fs) DirCacheFlush() { f.dirCache.ResetRoot() }
