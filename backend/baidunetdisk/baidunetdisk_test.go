package baidunetdisk

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rclone/rclone/backend/baidunetdisk/api"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/object"
	"github.com/rclone/rclone/fstest/fstests"
	"github.com/rclone/rclone/lib/encoder"
	"github.com/rclone/rclone/lib/oauthutil"
	"github.com/rclone/rclone/lib/pacer"
	"github.com/rclone/rclone/lib/rest"
)

// TestIntegration runs the standard backend integration tests when TestBaiduNetdisk is configured.
func TestIntegration(t *testing.T) {
	fstests.Run(t, &fstests.Opt{
		RemoteName: "TestBaiduNetdisk:",
		NilObject:  (*Object)(nil),
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func jsonResponse(status int, value any) *http.Response {
	body, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

func testEncoder() encoder.MultiEncoder {
	return encoder.EncodeCtl |
		encoder.EncodeSlash |
		encoder.EncodeBackSlash |
		encoder.EncodeDoubleQuote |
		encoder.EncodeInvalidUtf8
}

func newTestFs(t *testing.T, transport http.RoundTripper) *Fs {
	t.Helper()

	ctx := context.Background()
	token, err := json.Marshal(map[string]any{
		"access_token": "token+/=value",
		"token_type":   "Bearer",
		"expiry":       time.Now().Add(time.Hour).Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	m := configmap.Simple{"token": string(token)}
	baseClient := &http.Client{Transport: transport}
	oauthClient, ts, err := oauthutil.NewClientWithBaseClient(ctx, "test", m, &oauthutil.Config{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		AuthURL:      "https://auth.example/authorize",
		TokenURL:     "https://auth.example/token",
	}, baseClient)
	if err != nil {
		t.Fatal(err)
	}
	f := &Fs{
		name:    "test",
		appRoot: "/apps/rclone",
		opt: Options{
			AppName: "rclone",
			Enc:     testEncoder(),
		},
		client: oauthClient,
		ts:     ts,
		pacer: fs.NewPacer(ctx, pacer.NewDefault(
			pacer.MinSleep(0),
			pacer.MaxSleep(0),
		)),
	}
	f.srv = rest.NewClient(f.client).SetRoot(rootURL).SetErrorHandler(errorHandler)
	return f
}

func TestOAuthOptionsAndConfigIsolation(t *testing.T) {
	ri, err := fs.Find("baidunetdisk")
	if err != nil {
		t.Fatal(err)
	}
	tokenOption := ri.Options.Get(config.ConfigToken)
	if tokenOption == nil || !tokenOption.Sensitive {
		t.Fatal("OAuth token option must be registered as sensitive")
	}
	secretOption := ri.Options.Get(config.ConfigClientSecret)
	if secretOption == nil || !secretOption.Sensitive {
		t.Fatal("OAuth client_secret option must be registered as sensitive")
	}
	if oauthConfig.ClientID == "" || oauthConfig.ClientSecret == "" {
		t.Fatal("built-in OAuth credentials must be available to the config wizard")
	}

	originalID, originalSecret := oauthConfig.ClientID, oauthConfig.ClientSecret
	m := configmap.Simple{
		"client_id":     "custom-client",
		"client_secret": "custom-secret",
		"app_name":      "rclone",
		"token":         `{"access_token":"test","token_type":"Bearer","expiry":"2099-01-01T00:00:00Z"}`,
	}
	_, err = NewFs(context.Background(), "test", "", m)
	if err != nil {
		t.Fatal(err)
	}
	if oauthConfig.ClientID != originalID || oauthConfig.ClientSecret != originalSecret {
		t.Fatal("NewFs mutated the package OAuth config")
	}
}

func TestAPIResponsesAcceptStringRequestID(t *testing.T) {
	var result api.SuperfileResponse
	if err := json.Unmarshal([]byte(`{"errno":0,"request_id":"123"}`), &result); err != nil {
		t.Fatalf("failed to decode string request_id: %v", err)
	}
}

func TestAbsPathEncodesProviderNames(t *testing.T) {
	f := &Fs{
		root:    "root",
		appRoot: "/apps/rclone",
		opt:     Options{Enc: testEncoder()},
	}
	remote := `dir/name\with-control` + string(rune(1))
	want := "/apps/rclone/" + f.opt.Enc.FromStandardPath(path.Join(f.root, remote))
	if got := f.absPath(remote); got != want {
		t.Fatalf("absPath() = %q, want %q", got, want)
	}
}

func TestNewObjectRejectsPathTraversal(t *testing.T) {
	var calls int
	f := newTestFs(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return jsonResponse(http.StatusOK, api.ListResponse{}), nil
	}))

	_, err := f.NewObject(context.Background(), "../outside")
	if err == nil || !strings.Contains(err.Error(), "path traversal") {
		t.Fatalf("NewObject() error = %v, want path traversal error", err)
	}
	if calls != 0 {
		t.Fatalf("path traversal made %d HTTP requests, want 0", calls)
	}
}

func TestValidateAppName(t *testing.T) {
	for _, appName := range []string{"", ".", "..", "parent/child", `parent\child`} {
		if err := validateAppName(appName); err == nil {
			t.Errorf("validateAppName(%q) accepted an unsafe app name", appName)
		}
	}
	if err := validateAppName("rclone"); err != nil {
		t.Fatalf("validateAppName(rclone) = %v", err)
	}
}

func TestPrecisionReportsUnsupportedModTime(t *testing.T) {
	f := new(Fs)
	if got := f.Precision(); got != fs.ModTimeNotSupported {
		t.Fatalf("Precision() = %v, want %v", got, fs.ModTimeNotSupported)
	}
}

func TestGetFileInfoPaginates(t *testing.T) {
	var calls int
	f := newTestFs(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		start := req.URL.Query().Get("start")
		switch start {
		case "0", "":
			files := make([]*api.File, listPageSize)
			for i := range files {
				files[i] = &api.File{ServerFilename: "other-" + string(rune(i))}
			}
			return jsonResponse(http.StatusOK, api.ListResponse{
				List:    files,
				HasMore: 1,
			}), nil
		case "1000":
			return jsonResponse(http.StatusOK, api.ListResponse{
				List: []*api.File{{
					FsID:           42,
					ServerFilename: "target",
					Path:           "/apps/rclone/target",
				}},
			}), nil
		default:
			t.Fatalf("unexpected start parameter %q", start)
			return nil, nil
		}
	}))

	info, err := f.getFileInfo(context.Background(), "/apps/rclone/target")
	if err != nil {
		t.Fatal(err)
	}
	if info.FsID != 42 {
		t.Fatalf("FsID = %d, want 42", info.FsID)
	}
	if calls != 2 {
		t.Fatalf("HTTP calls = %d, want 2", calls)
	}
}

func TestRmdirRefusesNonEmptyDirectory(t *testing.T) {
	var deleteCalls int
	f := newTestFs(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPost {
			deleteCalls++
			return jsonResponse(http.StatusOK, api.FileManagerResponse{}), nil
		}
		return jsonResponse(http.StatusOK, api.ListResponse{
			List: []*api.File{{
				FsID:           1,
				ServerFilename: "child",
				Path:           "/apps/rclone/dir/child",
			}},
		}), nil
	}))

	err := f.Rmdir(context.Background(), "dir")
	if !errors.Is(err, fs.ErrorDirectoryNotEmpty) {
		t.Fatalf("Rmdir() error = %v, want %v", err, fs.ErrorDirectoryNotEmpty)
	}
	if deleteCalls != 0 {
		t.Fatalf("Rmdir made %d delete calls, want 0", deleteCalls)
	}
}

func TestFileManagerChecksItemErrors(t *testing.T) {
	f := newTestFs(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, api.FileManagerResponse{
			Info: []*api.FileOpInfo{{
				Errno: api.ErrnoFileNotExist,
				Path:  "/apps/rclone/missing",
			}},
		}), nil
	}))

	err := f.fileManager(context.Background(), api.FileManagerOpMove, "/apps/rclone/missing", "/apps/rclone", "new")
	var apiErr *api.Error
	if !errors.As(err, &apiErr) || apiErr.Errno != api.ErrnoFileNotExist {
		t.Fatalf("fileManager() error = %v, want API error %d", err, api.ErrnoFileNotExist)
	}
}

func TestFileManagerRequestsOverwrite(t *testing.T) {
	var ondup string
	f := newTestFs(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}
		ondup = form.Get("ondup")
		return jsonResponse(http.StatusOK, api.FileManagerResponse{}), nil
	}))

	if err := f.fileManager(context.Background(), api.FileManagerOpCopy, "/apps/rclone/source", "/apps/rclone", "target"); err != nil {
		t.Fatal(err)
	}
	if ondup != "overwrite" {
		t.Fatalf("filemanager ondup = %q, want overwrite", ondup)
	}
}

func TestWaitForTaskChecksAPIError(t *testing.T) {
	f := newTestFs(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, api.TaskQueryResponse{
			Errno: api.ErrnoTaskNotFound,
		}), nil
	}))

	err := f.waitForTask(context.Background(), 123)
	var apiErr *api.Error
	if !errors.As(err, &apiErr) || apiErr.Errno != api.ErrnoTaskNotFound {
		t.Fatalf("waitForTask() error = %v, want API error %d", err, api.ErrnoTaskNotFound)
	}
}

func TestShouldRetryHTTPStatusWithoutTransportError(t *testing.T) {
	retry, err := shouldRetry(context.Background(), &http.Response{
		StatusCode: http.StatusInternalServerError,
		Status:     "500 Internal Server Error",
	}, nil)
	if !retry {
		t.Fatal("shouldRetry() = false, want true")
	}
	if err == nil {
		t.Fatal("shouldRetry() returned a nil error for a retryable HTTP status")
	}
}

func TestDownloadUserAgentMeetsBaiduRequirement(t *testing.T) {
	if !strings.Contains(baiduUserAgent, "pan.baidu.com") {
		t.Fatalf("download User-Agent %q does not contain pan.baidu.com", baiduUserAgent)
	}
}

func TestOpenRetriesAndEscapesToken(t *testing.T) {
	var downloadCalls int
	f := newTestFs(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Host {
		case "pan.baidu.com":
			return jsonResponse(http.StatusOK, api.FileMetasResponse{
				List: []*api.File{{
					DLink: "https://download.example/file?existing=1",
				}},
			}), nil
		case "download.example":
			downloadCalls++
			if got := req.URL.Query().Get("access_token"); got != "token+/=value" {
				t.Fatalf("access_token = %q, want exact token", got)
			}
			if got := req.Header.Get("User-Agent"); got != baiduUserAgent {
				t.Fatalf("User-Agent = %q, want %q", got, baiduUserAgent)
			}
			if downloadCalls == 1 {
				return jsonResponse(http.StatusInternalServerError, map[string]any{
					"errno": 500,
				}), nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("payload")),
			}, nil
		default:
			t.Fatalf("unexpected host %q", req.URL.Host)
			return nil, nil
		}
	}))
	o := &Object{fs: f, fsID: 1, size: 7}

	body, err := o.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = body.Close() }()
	data, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "payload" {
		t.Fatalf("downloaded %q, want payload", data)
	}
	if downloadCalls != 2 {
		t.Fatalf("download calls = %d, want 2", downloadCalls)
	}
}

func TestCalculateBlockHashesHonorsDeclaredSize(t *testing.T) {
	o := new(Object)

	reader := bytes.NewReader([]byte("abcdef"))
	hashes, err := o.calculateBlockHashes(reader, 3)
	if err != nil {
		t.Fatal(err)
	}
	wantHash := md5.Sum([]byte("abc"))
	want := hex.EncodeToString(wantHash[:])
	if len(hashes) != 1 || hashes[0] != want {
		t.Fatalf("hashes = %v, want [%s]", hashes, want)
	}
	if offset, err := reader.Seek(0, io.SeekCurrent); err != nil || offset != 3 {
		t.Fatalf("reader offset = %d, %v; want 3, nil", offset, err)
	}

	_, err = o.calculateBlockHashes(bytes.NewReader([]byte("abc")), 6)
	if err == nil {
		t.Fatal("calculateBlockHashes accepted a reader shorter than the declared size")
	}
}

func TestOffsetReadSeekerUsesInitialPositionAsStart(t *testing.T) {
	reader := bytes.NewReader([]byte("prefixpayloadsuffix"))
	if _, err := reader.Seek(int64(len("prefix")), io.SeekStart); err != nil {
		t.Fatal(err)
	}
	offsetReader := &offsetReadSeeker{ReadSeeker: reader, base: int64(len("prefix"))}
	o := new(Object)

	hashes, err := o.calculateBlockHashes(offsetReader, int64(len("payload")))
	if err != nil {
		t.Fatal(err)
	}
	wantHash := md5.Sum([]byte("payload"))
	if len(hashes) != 1 || hashes[0] != hex.EncodeToString(wantHash[:]) {
		t.Fatalf("hashes = %v, want hash of payload", hashes)
	}
	if _, err := offsetReader.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, len("payload"))
	if _, err := io.ReadFull(offsetReader, data); err != nil {
		t.Fatal(err)
	}
	if string(data) != "payload" {
		t.Fatalf("read %q, want payload", data)
	}
}

func TestCallJSONReplaysFormBodyOnRetry(t *testing.T) {
	var bodies [][]byte
	f := newTestFs(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body)
		if len(bodies) == 1 {
			return jsonResponse(http.StatusInternalServerError, api.Error{Errno: 500}), nil
		}
		return jsonResponse(http.StatusOK, api.CreateResponse{}), nil
	}))

	if err := f.Mkdir(context.Background(), "retry-dir"); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 2 {
		t.Fatalf("request count = %d, want 2", len(bodies))
	}
	if len(bodies[0]) == 0 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("form request body was not replayed exactly on retry")
	}
}

func TestPutStreamSpoolsUnknownSize(t *testing.T) {
	const payload = "streamed payload"
	var uploadCalls int
	var finalized bool
	f := newTestFs(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Host {
		case "d.pcs.baidu.com":
			uploadCalls++
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(body, []byte(payload)) {
				t.Fatalf("upload body does not contain %q", payload)
			}
			return jsonResponse(http.StatusOK, api.SuperfileResponse{}), nil
		case "pan.baidu.com":
			method := req.URL.Query().Get("method")
			if req.Method == http.MethodGet && method == "list" {
				return jsonResponse(http.StatusOK, api.ListResponse{List: []*api.File{{
					FsID:           42,
					ServerFilename: "stream.bin",
					Path:           "/apps/rclone/stream.bin",
					Size:           int64(len(payload)),
				}}}), nil
			}
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatal(err)
			}
			form, err := url.ParseQuery(string(body))
			if err != nil {
				t.Fatal(err)
			}
			switch method {
			case "precreate":
				if got := form.Get("size"); got != strconv.Itoa(len(payload)) {
					t.Fatalf("precreate size = %q, want %d", got, len(payload))
				}
				if got := form.Get("rtype"); got != "2" {
					return jsonResponse(http.StatusBadRequest, api.Error{Errno: 2}), nil
				}
				return jsonResponse(http.StatusOK, api.PrecreateResponse{
					UploadID:   "upload-id",
					ReturnType: 1,
					BlockList:  []int{0},
				}), nil
			case "create":
				if form.Get("isdir") == "1" {
					return jsonResponse(http.StatusOK, api.CreateResponse{}), nil
				}
				if form.Get("rtype") != "2" {
					return jsonResponse(http.StatusBadRequest, api.Error{Errno: 2}), nil
				}
				finalized = true
				return jsonResponse(http.StatusOK, api.CreateResponse{
					FsID: 42,
					Path: "/apps/rclone/stream.bin",
					Size: int64(len(payload)),
				}), nil
			default:
				t.Fatalf("unexpected Baidu method %q", method)
				return nil, nil
			}
		default:
			t.Fatalf("unexpected host %q", req.URL.Host)
			return nil, nil
		}
	}))
	src := object.NewStaticObjectInfo("stream.bin", time.Now(), -1, true, nil, f)

	obj, err := f.PutStream(context.Background(), strings.NewReader(payload), src)
	if err != nil {
		t.Fatal(err)
	}
	if uploadCalls != 1 || !finalized {
		t.Fatalf("upload calls = %d, finalized = %v; want 1, true", uploadCalls, finalized)
	}
	if obj.Size() != int64(len(payload)) {
		t.Fatalf("object size = %d, want %d", obj.Size(), len(payload))
	}
}

func TestEmptyUploadUsesMultipartFlow(t *testing.T) {
	var precreated, uploaded, finalized bool
	f := newTestFs(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "d.pcs.baidu.com" {
			uploaded = true
			return jsonResponse(http.StatusOK, api.SuperfileResponse{}), nil
		}

		method := req.URL.Query().Get("method")
		if req.Method == http.MethodGet && method == "list" {
			return jsonResponse(http.StatusOK, api.ListResponse{List: []*api.File{{
				FsID:           43,
				ServerFilename: "empty.bin",
				Path:           "/apps/rclone/empty.bin",
			}}}), nil
		}
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}
		switch method {
		case "precreate":
			precreated = true
			if form.Get("size") != "0" {
				return jsonResponse(http.StatusBadRequest, api.Error{Errno: 2}), nil
			}
			return jsonResponse(http.StatusOK, api.PrecreateResponse{
				UploadID:   "empty-upload-id",
				ReturnType: 1,
				BlockList:  []int{0},
			}), nil
		case "create":
			if form.Get("isdir") == "1" {
				return jsonResponse(http.StatusOK, api.CreateResponse{}), nil
			}
			if form.Get("uploadid") != "empty-upload-id" {
				return jsonResponse(http.StatusBadRequest, api.Error{Errno: 2}), nil
			}
			finalized = true
			return jsonResponse(http.StatusOK, api.CreateResponse{
				FsID: 43,
				Path: "/apps/rclone/empty.bin",
			}), nil
		default:
			return jsonResponse(http.StatusBadRequest, api.Error{Errno: 2}), nil
		}
	}))
	src := object.NewStaticObjectInfo("empty.bin", time.Now(), 0, true, nil, f)

	obj, err := f.Put(context.Background(), strings.NewReader(""), src)
	if err != nil {
		t.Fatal(err)
	}
	if !precreated || !uploaded || !finalized {
		t.Fatalf("precreated = %v, uploaded = %v, finalized = %v; want all true", precreated, uploaded, finalized)
	}
	if obj.Size() != 0 {
		t.Fatalf("object size = %d, want 0", obj.Size())
	}
}

func TestUploadBlockRetriesWithReplayableBody(t *testing.T) {
	var calls int
	var bodies [][]byte
	f := newTestFs(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if got := req.URL.Query().Get("access_token"); got != "token+/=value" {
			t.Fatalf("access_token = %q, want exact token", got)
		}
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body)
		if calls == 1 {
			return jsonResponse(http.StatusInternalServerError, map[string]any{
				"errno": 500,
			}), nil
		}
		return jsonResponse(http.StatusOK, api.SuperfileResponse{}), nil
	}))
	o := &Object{fs: f, remote: "file"}

	err := o.uploadBlock(context.Background(), bytes.NewReader([]byte("hello")), "/apps/rclone/file", "upload-id", 0, 5)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("upload calls = %d, want 2", calls)
	}
	if len(bodies[0]) == 0 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("multipart upload body was not replayed exactly on retry")
	}
	if !bytes.Contains(bodies[0], []byte("hello")) {
		t.Fatal("multipart upload body did not contain the chunk")
	}
}
