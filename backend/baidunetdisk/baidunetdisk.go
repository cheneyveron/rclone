// Package baidunetdisk provides an interface to Baidu Netdisk (百度网盘) xPan API
package baidunetdisk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rclone/rclone/backend/baidunetdisk/api"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/fserrors"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/encoder"
	"github.com/rclone/rclone/lib/oauthutil"
	"github.com/rclone/rclone/lib/pacer"
	"github.com/rclone/rclone/lib/rest"
)

// Constants
const (
	rcloneClientID     = "HMHCuMZzPBj02oGjm4LKLQGE8v8MsyK6"
	rcloneClientSecret = "bUF3tdHJYxQQHwCT9J0JBP8Ll3J4sMwi"

	minSleep       = 10 * time.Millisecond
	maxSleep       = 2 * time.Second
	decayConstant  = 2
	rootURL        = "https://pan.baidu.com"
	uploadRootURL  = "https://d.pcs.baidu.com"
	defaultAppName = "rclone" // App folder name in /apps/

	// Baidu requires this User-Agent for downloads
	baiduUserAgent = "netdisk;7.0.3.2;PC;PC-Windows;10.0.19043;WindowsBaiduYunGuanJia"

	// Upload chunk size - Baidu requires 4MB chunks
	defaultChunkSize = 4 * 1024 * 1024 // 4MB

	// List limit per page
	listPageSize = 1000
)

// Globals
var (
	oauthConfig = oauthutil.Config{
		Scopes: []string{
			"basic",
			"netdisk",
		},
		AuthURL:     "https://openapi.baidu.com/oauth/2.0/authorize",
		TokenURL:    "https://openapi.baidu.com/oauth/2.0/token",
		RedirectURL: oauthutil.RedirectURL,
	}
)

// Register with Fs
func init() {
	fs.Register(&fs.RegInfo{
		Name:        "baidunetdisk",
		Description: "Baidu Netdisk (百度网盘)",
		NewFs:       NewFs,
		Config: func(ctx context.Context, name string, m configmap.Mapper, config fs.ConfigIn) (*fs.ConfigOut, error) {
			return oauthutil.ConfigOut("", &oauthutil.Options{
				OAuth2Config: &oauthConfig,
			})
		},
		Options: []fs.Option{{
			Name:     "client_id",
			Help:     "OAuth Client Id.\n\nLeave blank to use rclone's default client ID.",
			Advanced: true,
		}, {
			Name:     "client_secret",
			Help:     "OAuth Client Secret.\n\nLeave blank to use rclone's default client secret.",
			Advanced: true,
		}, {
			Name:     "app_name",
			Default:  defaultAppName,
			Help:     "App name in /apps/ folder.\n\nBaidu Netdisk stores files under /apps/{app_name}/ path.",
			Advanced: true,
		}, {
			Name:     config.ConfigEncoding,
			Help:     config.ConfigEncodingHelp,
			Advanced: true,
			Default: (encoder.EncodeCtl |
				encoder.EncodeSlash |
				encoder.EncodeBackSlash |
				encoder.EncodeDoubleQuote |
				encoder.EncodeInvalidUtf8),
		}},
	})
}

// Options defines the configuration for this backend
type Options struct {
	ClientID     string               `config:"client_id"`
	ClientSecret string               `config:"client_secret"`
	AppName      string               `config:"app_name"`
	Enc          encoder.MultiEncoder `config:"encoding"`
}

// Fs represents a remote Baidu Netdisk
type Fs struct {
	name     string       // name of this remote
	root     string       // the path we are working on (relative to /apps/{app_name}/)
	appRoot  string       // /apps/{app_name}
	opt      Options      // parsed options
	features *fs.Features // optional features
	srv      *rest.Client // the connection to the server
	pacer    *fs.Pacer    // pacer for API calls
	client   *http.Client // authorized http client
	ts       *oauthutil.TokenSource
	m        configmap.Mapper
	mu       sync.Mutex // protect token refresh
}

// Object describes a Baidu Netdisk object
type Object struct {
	fs      *Fs       // reference to the Fs
	remote  string    // the remote path
	size    int64     // size of the object
	modTime time.Time // modification time
	fsID    int64     // file system ID
	md5     string    // MD5 hash
	path    string    // full path on Baidu Netdisk
}

// ------------------------------------------------------------

// Name of the remote (as passed into NewFs)
func (f *Fs) Name() string {
	return f.name
}

// Root of the remote (as passed into NewFs)
func (f *Fs) Root() string {
	return f.root
}

// String converts this Fs to a string
func (f *Fs) String() string {
	return fmt.Sprintf("Baidu Netdisk root '%s'", f.root)
}

// Features returns the optional features of this Fs
func (f *Fs) Features() *fs.Features {
	return f.features
}

// Precision return the precision of this Fs
func (f *Fs) Precision() time.Duration {
	return time.Second
}

// Hashes returns the supported hash sets
func (f *Fs) Hashes() hash.Set {
	return hash.Set(hash.MD5)
}

// ------------------------------------------------------------

// parsePath parses a Baidu Netdisk path
func parsePath(p string) string {
	return strings.Trim(p, "/")
}

// absPath returns the absolute path on Baidu Netdisk
func (f *Fs) absPath(remote string) string {
	// Build the path without trailing slashes
	if f.root == "" && remote == "" {
		return f.appRoot
	}
	if remote == "" {
		return f.appRoot + "/" + f.root
	}
	return f.appRoot + "/" + path.Join(f.root, remote)
}

// relPath returns the relative path from the appRoot
func (f *Fs) relPath(absPath string) string {
	prefix := f.appRoot + "/"
	if strings.HasPrefix(absPath, prefix) {
		result := strings.TrimPrefix(absPath, prefix)
		if f.root != "" && strings.HasPrefix(result, f.root+"/") {
			return strings.TrimPrefix(result, f.root+"/")
		} else if result == f.root {
			return ""
		}
		return result
	}
	return absPath
}

// errorHandler parses a non 2xx error response into an error
func errorHandler(resp *http.Response) error {
	body, err := rest.ReadBody(resp)
	if err != nil {
		return fmt.Errorf("error reading error response: %w", err)
	}

	var apiErr api.Error
	if err = json.Unmarshal(body, &apiErr); err != nil {
		return fmt.Errorf("HTTP error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if apiErr.Errno != 0 {
		return &apiErr
	}
	return fmt.Errorf("HTTP error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
}

// shouldRetry returns whether this error should be retried
func shouldRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
	if fserrors.ContextError(ctx, &err) {
		return false, err
	}
	if err == nil {
		return false, nil
	}

	// Retry on rate limit
	if resp != nil && resp.StatusCode == 429 {
		return true, err
	}

	// Check for specific Baidu errors
	var apiErr *api.Error
	if errors.As(err, &apiErr) {
		switch apiErr.Errno {
		case api.ErrnoAccessTokenInvalid, api.ErrnoAccessTokenExpired, api.ErrnoRefreshTokenInvalid:
			// Token errors should trigger re-auth
			return false, fserrors.FatalError(err)
		case api.ErrnoInsufficientSpace:
			return false, fserrors.FatalError(err)
		case api.ErrnoUserNotAuthorized:
			// Error -6: User not authorized - this usually means app_name mismatch
			return false, fserrors.FatalError(fmt.Errorf("baidu: user not authorized (error -6). This usually means your 'app_name' config doesn't match your registered Baidu app name. Check your Baidu developer console for the correct app name and set it with 'rclone config' -> Advanced config -> app_name"))
		}
	}

	return fserrors.ShouldRetry(err), err
}

// getClient creates an HTTP client with the auth token
func (f *Fs) getClient(ctx context.Context) *http.Client {
	return fshttp.NewClient(ctx)
}

// NewFs constructs an Fs from the path, container:path
func NewFs(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
	opt := new(Options)
	err := configstruct.Set(m, opt)
	if err != nil {
		return nil, err
	}

	// Override client credentials if provided
	if opt.ClientID != "" && opt.ClientSecret != "" {
		oauthConfig.ClientID = opt.ClientID
		oauthConfig.ClientSecret = opt.ClientSecret
	} else {
		oauthConfig.ClientID = rcloneClientID
		oauthConfig.ClientSecret = rcloneClientSecret
	}

	oAuthClient, ts, err := oauthutil.NewClient(ctx, name, m, &oauthConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create oauth client: %w", err)
	}

	f := &Fs{
		name:    name,
		root:    parsePath(root),
		appRoot: "/apps/" + opt.AppName,
		opt:     *opt,
		client:  oAuthClient,
		ts:      ts,
		m:       m,
		pacer:   fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant))),
	}

	f.features = (&fs.Features{
		CanHaveEmptyDirectories: true,
		ReadMimeType:            false,
		WriteMimeType:           false,
	}).Fill(ctx, f)

	// Create REST client
	f.srv = rest.NewClient(f.client).SetRoot(rootURL).SetErrorHandler(errorHandler)

	// Check if root exists and is a file
	absRoot := f.absPath("")
	if f.root != "" {
		info, err := f.getFileInfo(ctx, absRoot)
		if err == nil {
			if info.IsDir == 0 {
				// Root is a file
				f.root = path.Dir(f.root)
				return f, fs.ErrorIsFile
			}
		}
	}

	return f, nil
}

// addToken adds access_token to the URL parameters
func (f *Fs) addToken(params url.Values) error {
	token, err := f.ts.Token()
	if err != nil {
		return fmt.Errorf("failed to get access token: %w", err)
	}
	params.Set("access_token", token.AccessToken)
	return nil
}

// getFileInfo gets file info from path
func (f *Fs) getFileInfo(ctx context.Context, absPath string) (*api.File, error) {
	// First, try to get the parent directory listing to find the file
	parentPath := path.Dir(absPath)
	filename := path.Base(absPath)

	params := url.Values{
		"method": {"list"},
		"dir":    {parentPath},
		"limit":  {strconv.Itoa(listPageSize)},
	}
	if err := f.addToken(params); err != nil {
		return nil, err
	}

	opts := rest.Opts{
		Method:     "GET",
		Path:       "/rest/2.0/xpan/file",
		Parameters: params,
	}

	var result api.ListResponse
	var resp *http.Response
	var err error
	err = f.pacer.Call(func() (bool, error) {
		resp, err = f.srv.CallJSON(ctx, &opts, nil, &result)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return nil, err
	}
	if result.Errno != 0 {
		return nil, &api.Error{Errno: result.Errno}
	}

	for _, file := range result.List {
		if file.ServerFilename == filename {
			return file, nil
		}
	}

	return nil, fs.ErrorObjectNotFound
}

// getFileMetas gets file metadata including download link
func (f *Fs) getFileMetas(ctx context.Context, fsIDs []int64) ([]*api.File, error) {
	fsIDsJSON, err := json.Marshal(fsIDs)
	if err != nil {
		return nil, err
	}

	params := url.Values{
		"method": {"filemetas"},
		"fsids":  {string(fsIDsJSON)},
		"dlink":  {"1"},
	}
	if err := f.addToken(params); err != nil {
		return nil, err
	}

	opts := rest.Opts{
		Method:     "GET",
		Path:       "/rest/2.0/xpan/multimedia",
		Parameters: params,
	}

	var result api.FileMetasResponse
	var resp *http.Response
	err = f.pacer.Call(func() (bool, error) {
		resp, err = f.srv.CallJSON(ctx, &opts, nil, &result)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return nil, err
	}
	if result.Errno != 0 {
		return nil, &api.Error{Errno: result.Errno}
	}

	return result.List, nil
}

// List the objects and directories in dir into entries
func (f *Fs) List(ctx context.Context, dir string) (entries fs.DirEntries, err error) {
	absDir := f.absPath(dir)

	start := 0
	for {
		params := url.Values{
			"method": {"list"},
			"dir":    {absDir},
			"start":  {strconv.Itoa(start)},
			"limit":  {strconv.Itoa(listPageSize)},
		}
		if err := f.addToken(params); err != nil {
			return nil, err
		}

		opts := rest.Opts{
			Method:     "GET",
			Path:       "/rest/2.0/xpan/file",
			Parameters: params,
		}

		var result api.ListResponse
		var resp *http.Response
		err = f.pacer.Call(func() (bool, error) {
			resp, err = f.srv.CallJSON(ctx, &opts, nil, &result)
			return shouldRetry(ctx, resp, err)
		})
		if err != nil {
			return nil, err
		}
		if result.Errno != 0 {
			if result.Errno == api.ErrnoPathNotExist || result.Errno == api.ErrnoFileNotExist {
				return nil, fs.ErrorDirNotFound
			}
			return nil, &api.Error{Errno: result.Errno}
		}

		for _, item := range result.List {
			remote := path.Join(dir, f.opt.Enc.ToStandardName(item.ServerFilename))
			if item.IsDir == 1 {
				d := fs.NewDir(remote, item.ServerMtime.Time())
				entries = append(entries, d)
			} else {
				o := &Object{
					fs:      f,
					remote:  remote,
					size:    item.Size,
					modTime: item.ServerMtime.Time(),
					fsID:    item.FsID,
					md5:     item.MD5,
					path:    item.Path,
				}
				entries = append(entries, o)
			}
		}

		if len(result.List) < listPageSize {
			break
		}
		start += len(result.List)
	}

	return entries, nil
}

// NewObject finds the Object at remote
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	absPath := f.absPath(remote)
	info, err := f.getFileInfo(ctx, absPath)
	if err != nil {
		return nil, err
	}
	if info.IsDir == 1 {
		return nil, fs.ErrorIsDir
	}

	return &Object{
		fs:      f,
		remote:  remote,
		size:    info.Size,
		modTime: info.ServerMtime.Time(),
		fsID:    info.FsID,
		md5:     info.MD5,
		path:    info.Path,
	}, nil
}

// Put uploads a file
func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	// Check if the input is seekable
	seeker, ok := in.(io.ReadSeeker)
	if !ok {
		return nil, errors.New("baidu backend requires a seekable input (local file); streaming upload is not supported. Please use --vfs-cache-mode writes if mounting")
	}

	remote := src.Remote()
	size := src.Size()

	o := &Object{
		fs:     f,
		remote: remote,
	}

	err := o.upload(ctx, seeker, size, options...)
	if err != nil {
		return nil, err
	}

	return o, nil
}

// Mkdir creates the directory if it doesn't exist
func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	absPath := f.absPath(dir)
	return f.mkdir(ctx, absPath)
}

// mkdir creates a directory at the absolute path
func (f *Fs) mkdir(ctx context.Context, absPath string) error {
	params := url.Values{
		"method": {"create"},
	}
	if err := f.addToken(params); err != nil {
		return err
	}

	form := url.Values{
		"path":  {absPath},
		"size":  {"0"},
		"isdir": {"1"},
		"rtype": {"0"},
	}

	opts := rest.Opts{
		Method:      "POST",
		Path:        "/rest/2.0/xpan/file",
		ContentType: "application/x-www-form-urlencoded",
		Parameters:  params,
		Body:        strings.NewReader(form.Encode()),
	}

	var result api.CreateResponse
	var resp *http.Response
	var err error
	err = f.pacer.Call(func() (bool, error) {
		resp, err = f.srv.CallJSON(ctx, &opts, nil, &result)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return err
	}
	if result.Errno != 0 && result.Errno != api.ErrnoFileAlreadyExist && result.Errno != api.ErrnoFileAlreadyExist2 {
		return &api.Error{Errno: result.Errno}
	}

	return nil
}

// Rmdir removes the directory if empty
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	absPath := f.absPath(dir)
	return f.delete(ctx, absPath)
}

// delete removes a file or empty directory
func (f *Fs) delete(ctx context.Context, absPath string) error {
	fileList, err := json.Marshal([]string{absPath})
	if err != nil {
		return err
	}

	params := url.Values{
		"method": {"filemanager"},
		"opera":  {"delete"},
	}
	if err := f.addToken(params); err != nil {
		return err
	}

	form := url.Values{
		"async":    {"0"},
		"filelist": {string(fileList)},
	}

	opts := rest.Opts{
		Method:      "POST",
		Path:        "/rest/2.0/xpan/file",
		ContentType: "application/x-www-form-urlencoded",
		Parameters:  params,
		Body:        strings.NewReader(form.Encode()),
	}

	var result api.FileManagerResponse
	var resp *http.Response
	var err2 error
	err2 = f.pacer.Call(func() (bool, error) {
		resp, err2 = f.srv.CallJSON(ctx, &opts, nil, &result)
		return shouldRetry(ctx, resp, err2)
	})
	if err2 != nil {
		return err2
	}
	if result.Errno != 0 {
		return &api.Error{Errno: result.Errno}
	}

	return nil
}

// Copy copies a remote object
func (f *Fs) Copy(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	srcObj, ok := src.(*Object)
	if !ok {
		fs.Debugf(src, "Can't copy - not same remote type")
		return nil, fs.ErrorCantCopy
	}

	srcPath := srcObj.path
	dstPath := f.absPath(remote)
	dstDir := path.Dir(dstPath)
	dstName := path.Base(dstPath)

	err := f.fileManager(ctx, api.FileManagerOpCopy, srcPath, dstDir, dstName)
	if err != nil {
		return nil, err
	}

	return f.NewObject(ctx, remote)
}

// Move moves a remote object
func (f *Fs) Move(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	srcObj, ok := src.(*Object)
	if !ok {
		fs.Debugf(src, "Can't move - not same remote type")
		return nil, fs.ErrorCantMove
	}

	srcPath := srcObj.path
	dstPath := f.absPath(remote)
	dstDir := path.Dir(dstPath)
	dstName := path.Base(dstPath)

	err := f.fileManager(ctx, api.FileManagerOpMove, srcPath, dstDir, dstName)
	if err != nil {
		return nil, err
	}

	return f.NewObject(ctx, remote)
}

// DirMove moves a directory
func (f *Fs) DirMove(ctx context.Context, src fs.Fs, srcRemote, dstRemote string) error {
	srcFs, ok := src.(*Fs)
	if !ok {
		fs.Debugf(src, "Can't DirMove - not same remote type")
		return fs.ErrorCantDirMove
	}

	srcPath := srcFs.absPath(srcRemote)
	dstPath := f.absPath(dstRemote)
	dstDir := path.Dir(dstPath)
	dstName := path.Base(dstPath)

	return f.fileManager(ctx, api.FileManagerOpMove, srcPath, dstDir, dstName)
}

// fileManager performs file management operations (copy, move, delete, rename)
func (f *Fs) fileManager(ctx context.Context, op api.FileManagerOp, srcPath, destDir, newName string) error {
	fileList := []api.FileManagerItem{{
		Path:    srcPath,
		Dest:    destDir,
		NewName: newName,
	}}
	fileListJSON, err := json.Marshal(fileList)
	if err != nil {
		return err
	}

	params := url.Values{
		"method": {"filemanager"},
		"opera":  {string(op)},
	}
	if err := f.addToken(params); err != nil {
		return err
	}

	form := url.Values{
		"async":    {"2"}, // 0=sync, 1=adaptive, 2=async
		"filelist": {string(fileListJSON)},
	}

	opts := rest.Opts{
		Method:      "POST",
		Path:        "/rest/2.0/xpan/file",
		ContentType: "application/x-www-form-urlencoded",
		Parameters:  params,
		Body:        strings.NewReader(form.Encode()),
	}

	var result api.FileManagerResponse
	var resp *http.Response
	err = f.pacer.Call(func() (bool, error) {
		resp, err = f.srv.CallJSON(ctx, &opts, nil, &result)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return err
	}
	if result.Errno != 0 {
		return &api.Error{Errno: result.Errno}
	}

	// If async task, wait for it
	if result.TaskID != 0 {
		return f.waitForTask(ctx, result.TaskID)
	}

	return nil
}

// waitForTask waits for an async task to complete
func (f *Fs) waitForTask(ctx context.Context, taskID int64) error {
	for {
		params := url.Values{
			"method":  {"taskquery"},
			"task_id": {strconv.FormatInt(taskID, 10)},
		}
		if err := f.addToken(params); err != nil {
			return err
		}

		opts := rest.Opts{
			Method:     "GET",
			Path:       "/rest/2.0/xpan/file",
			Parameters: params,
		}

		var result api.TaskQueryResponse
		var resp *http.Response
		var err error
		err = f.pacer.Call(func() (bool, error) {
			resp, err = f.srv.CallJSON(ctx, &opts, nil, &result)
			return shouldRetry(ctx, resp, err)
		})
		if err != nil {
			return err
		}

		switch result.Status {
		case "success":
			return nil
		case "failed":
			return errors.New("async task failed")
		case "pending", "running":
			// Wait and check again
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(500 * time.Millisecond):
			}
		default:
			return fmt.Errorf("unknown task status: %s", result.Status)
		}
	}
}

// About gets quota information
func (f *Fs) About(ctx context.Context) (*fs.Usage, error) {
	params := url.Values{
		"checkfree":   {"1"},
		"checkexpire": {"1"},
	}
	if err := f.addToken(params); err != nil {
		return nil, err
	}

	opts := rest.Opts{
		Method:     "GET",
		Path:       "/api/quota",
		Parameters: params,
	}

	var result api.QuotaResponse
	var resp *http.Response
	var err error
	err = f.pacer.Call(func() (bool, error) {
		resp, err = f.srv.CallJSON(ctx, &opts, nil, &result)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return nil, err
	}
	if result.Errno != 0 {
		return nil, &api.Error{Errno: result.Errno}
	}

	return &fs.Usage{
		Total: fs.NewUsageValue(result.Total),
		Used:  fs.NewUsageValue(result.Used),
		Free:  fs.NewUsageValue(result.Free),
	}, nil
}

// ------------------------------------------------------------
// Object methods

// Fs returns the parent Fs
func (o *Object) Fs() fs.Info {
	return o.fs
}

// Remote returns the remote path
func (o *Object) Remote() string {
	return o.remote
}

// String returns a string representation
func (o *Object) String() string {
	if o == nil {
		return "<nil>"
	}
	return o.remote
}

// Size returns the size of the object
func (o *Object) Size() int64 {
	return o.size
}

// ModTime returns the modification time
func (o *Object) ModTime(ctx context.Context) time.Time {
	return o.modTime
}

// SetModTime sets the modification time (not supported)
func (o *Object) SetModTime(ctx context.Context, modTime time.Time) error {
	return fs.ErrorCantSetModTime
}

// Storable returns whether the object is storable
func (o *Object) Storable() bool {
	return true
}

// Hash returns the MD5 hash
func (o *Object) Hash(ctx context.Context, ty hash.Type) (string, error) {
	if ty != hash.MD5 {
		return "", hash.ErrUnsupported
	}
	return strings.ToLower(o.md5), nil
}

// Open opens the object for reading
func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (io.ReadCloser, error) {
	// Get fresh download link
	files, err := o.fs.getFileMetas(ctx, []int64{o.fsID})
	if err != nil {
		return nil, fmt.Errorf("failed to get download link: %w", err)
	}
	if len(files) == 0 {
		return nil, fs.ErrorObjectNotFound
	}

	dlink := files[0].DLink
	if dlink == "" {
		return nil, errors.New("no download link available")
	}

	// Get access token for download link
	token, err := o.fs.ts.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	// Add access token to download link
	if strings.Contains(dlink, "?") {
		dlink += "&access_token=" + token.AccessToken
	} else {
		dlink += "?access_token=" + token.AccessToken
	}

	// Create request with proper User-Agent
	req, err := http.NewRequestWithContext(ctx, "GET", dlink, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", baiduUserAgent)

	// Apply options (Range header for partial downloads)
	fs.FixRangeOption(options, o.size)
	fs.OpenOptionAddHTTPHeaders(req.Header, options)

	// Make request
	resp, err := o.fs.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download request failed: %w", err)
	}

	if resp.StatusCode >= 400 {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	return resp.Body, nil
}

// Update updates the object with new content
func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	// Check if the input is seekable
	seeker, ok := in.(io.ReadSeeker)
	if !ok {
		return errors.New("baidu backend requires a seekable input (local file); streaming upload is not supported. Please use --vfs-cache-mode writes if mounting")
	}

	return o.upload(ctx, seeker, src.Size(), options...)
}

// Remove removes the object
func (o *Object) Remove(ctx context.Context) error {
	return o.fs.delete(ctx, o.path)
}

// Check the interfaces are satisfied
var (
	_ fs.Fs       = (*Fs)(nil)
	_ fs.Copier   = (*Fs)(nil)
	_ fs.Mover    = (*Fs)(nil)
	_ fs.DirMover = (*Fs)(nil)
	_ fs.Abouter  = (*Fs)(nil)
	_ fs.Object   = (*Object)(nil)
)
