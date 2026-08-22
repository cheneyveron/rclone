package quark

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/obscure"
	"github.com/rclone/rclone/fs/object"
	"github.com/rclone/rclone/lib/dircache"
	"github.com/rclone/rclone/lib/encoder"
	"github.com/rclone/rclone/lib/pacer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestFs(t *testing.T, server *httptest.Server) (*Fs, configmap.Simple) {
	t.Helper()
	ctx := context.Background()
	config := configmap.Simple{}
	f := &Fs{
		name: "test",
		opt: Options{
			AccessToken: "access",
			UserID:      "user",
			DeviceID:    "device",
			ClientID:    "client",
			SignKey:     "sign-key",
			Enc:         encoder.MultiEncoder(encoder.EncodeInvalidUtf8),
		},
		client:       server.Client(),
		pacer:        fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(time.Millisecond), pacer.MaxSleep(2*time.Millisecond), pacer.DecayConstant(2))),
		config:       config,
		apiURL:       server.URL,
		accessToken:  "access",
		refreshToken: "refresh",
	}
	f.features = (&fs.Features{CanHaveEmptyDirectories: true, ReadMimeType: true}).Fill(ctx, f)
	f.dirCache = dircache.New("", "", f)
	return f, config
}

func checkSignedRequest(t *testing.T, request *http.Request, signKey string) {
	t.Helper()
	if got := request.URL.Query().Get("access_token"); got != "access" && got != "new-access" {
		t.Errorf("unexpected access token %q", got)
	}
	if got := request.Header.Get("x-pan-client-id"); got != "client" {
		t.Errorf("unexpected client ID %q", got)
	}
	timestamp := request.Header.Get("x-pan-tm")
	if _, err := strconv.ParseInt(timestamp, 10, 64); err != nil {
		t.Errorf("invalid timestamp %q: %v", timestamp, err)
	}
	plain := request.Method + "&" + request.URL.Path + "&" + timestamp + "&" + signKey
	sum := sha256.Sum256([]byte(plain))
	if got, want := request.Header.Get("x-pan-token"), hex.EncodeToString(sum[:]); got != want {
		t.Errorf("unexpected signature %q, want %q", got, want)
	}
}

func writeJSON(t *testing.T, writer http.ResponseWriter, value any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		t.Errorf("failed to write test response: %v", err)
	}
}

func TestNewFsAllowsMissingRefreshToken(t *testing.T) {
	config := configmap.Simple{
		"access_token": obscure.MustObscure("access"),
		"user_id":      "user",
		"device_id":    "device",
		"client_id":    "client",
		"sign_key":     "sign-key",
	}
	f, err := NewFs(context.Background(), "test", "", config)
	require.NoError(t, err)
	assert.Equal(t, "Quark Drive upload-only root \"\"", f.String())
}

func TestUnsupportedOpenPlatformOperations(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	f, _ := newTestFs(t, server)

	_, err := f.List(context.Background(), "")
	assert.ErrorIs(t, err, fs.ErrorNotImplemented)
	_, err = f.NewObject(context.Background(), "missing")
	assert.ErrorIs(t, err, fs.ErrorObjectNotFound)
	err = f.Rmdir(context.Background(), "dir")
	assert.ErrorIs(t, err, fs.ErrorNotImplemented)
	obj := &Object{fs: f, remote: "file"}
	_, err = obj.Open(context.Background())
	assert.ErrorIs(t, err, fs.ErrorNotImplemented)
	err = obj.Remove(context.Background())
	assert.ErrorIs(t, err, fs.ErrorNotImplemented)
}

func TestPutUsesOpenPlatformFormUploadFlow(t *testing.T) {
	const content = "abcdefg"
	var server *httptest.Server
	var uploadedParts int
	var firstPartAttempts int
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasPrefix(request.URL.Path, "/upload/") {
			if request.URL.Query().Get("access_token") != "" {
				t.Errorf("storage upload URL leaked the access token")
			}
			part, err := strconv.Atoi(strings.TrimPrefix(request.URL.Path, "/upload/"))
			if err != nil {
				t.Errorf("invalid upload part: %v", err)
			}
			if part == 1 {
				firstPartAttempts++
				if firstPartAttempts == 1 {
					writer.WriteHeader(http.StatusServiceUnavailable)
					return
				}
			}
			if got := request.Header.Get("Authorization"); got != fmt.Sprintf("signature-%d", part) {
				t.Errorf("unexpected storage authorization %q", got)
			}
			if got := request.Header.Get("X-Upload-Test"); got != "from-upload-pre" {
				t.Errorf("missing common upload header: %q", got)
			}
			data, err := io.ReadAll(request.Body)
			if err != nil {
				t.Errorf("failed to read upload part: %v", err)
			}
			if string(data) != content {
				t.Errorf("uploaded data was %q, want %q", data, content)
			}
			uploadedParts++
			writer.Header().Set("ETag", fmt.Sprintf("etag-%d", part))
			writer.WriteHeader(http.StatusOK)
			return
		}

		checkSignedRequest(t, request, "sign-key")
		switch request.URL.Path {
		case "/open/v1/dir":
			var body map[string]string
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("failed to decode directory request: %v", err)
			}
			fid := "fid-" + body["dir_path"]
			if body["dir_path"] == "snapshot" && body["pdir_fid"] != "" {
				t.Errorf("top-level directory unexpectedly had parent %q", body["pdir_fid"])
			}
			if body["dir_path"] == "sub" && body["pdir_fid"] != "fid-snapshot" {
				t.Errorf("subdirectory had parent %q", body["pdir_fid"])
			}
			writeJSON(t, writer, map[string]any{"status": 0, "data": map[string]any{"fid": fid}})
		case "/open/v1/file/upload_pre":
			var body uploadPreRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("failed to decode upload_pre request: %v", err)
			}
			if body.FileName != "file.txt" || body.ParentID != "fid-sub" || body.Size != int64(len(content)) {
				t.Errorf("unexpected upload_pre body: %+v", body)
			}
			if body.HashUpdate || body.SHA1 == "" || body.MD5 == "" || body.ProofVersion != "v1" || body.ProofCode1 == "" || body.ProofCode2 == "" {
				t.Errorf("missing hash or proof fields: %+v", body)
			}
			if len(body.PartInfo) != 1 || body.PartInfo[0].PartSize != int64(len(content)) || body.PartInfo[0].SHA1 == nil {
				t.Errorf("unexpected form upload part info: %+v", body.PartInfo)
			}
			writeJSON(t, writer, map[string]any{
				"status": 0,
				"data": map[string]any{
					"task_id":        "task",
					"common_headers": map[string]string{"X-Upload-Test": "from-upload-pre"},
					"upload_urls": []any{map[string]any{
						"part_number": 1,
						"upload_url":  server.URL + "/upload/1",
						"signature_info": map[string]string{
							"signature": "signature-1",
						},
					}},
				},
			})
		case "/open/v1/file/upload_finish":
			var body uploadFinishRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("failed to decode finish request: %v", err)
			}
			if len(body.PartInfo) != 1 || body.PartInfo[0].ETag != "etag-1" {
				t.Errorf("unexpected uploaded part list: %+v", body.PartInfo)
			}
			writeJSON(t, writer, map[string]any{"status": 0, "data": map[string]any{"finish": true, "fid": "file-fid"}})
		default:
			http.NotFound(writer, request)
		}
	})
	server = httptest.NewServer(handler)
	defer server.Close()
	f, _ := newTestFs(t, server)
	src := object.NewStaticObjectInfo("snapshot/sub/file.txt", time.Unix(123, 456_000_000), int64(len(content)), true, nil, f)

	obj, err := f.Put(context.Background(), bytes.NewBufferString(content), src)
	require.NoError(t, err)
	assert.Equal(t, "snapshot/sub/file.txt", obj.Remote())
	assert.Equal(t, int64(len(content)), obj.Size())
	assert.Equal(t, "file-fid", obj.(fs.IDer).ID())
	assert.Equal(t, 2, firstPartAttempts)
	assert.Equal(t, 1, uploadedParts)
}

func TestOpenPlatformMultipartUploadFlow(t *testing.T) {
	const partSize = int64(4 * fs.Mebi)
	content := bytes.Repeat([]byte("q"), int(formUploadLimit+1))
	var server *httptest.Server
	uploadedParts := 0
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasPrefix(request.URL.Path, "/multipart/") {
			part, err := strconv.Atoi(strings.TrimPrefix(request.URL.Path, "/multipart/"))
			if err != nil {
				t.Errorf("invalid multipart upload part: %v", err)
			}
			data, err := io.ReadAll(request.Body)
			if err != nil {
				t.Errorf("failed to read multipart upload: %v", err)
			}
			wantSize := partSize
			if part == 3 {
				wantSize = int64(2*fs.Mebi + 1)
			}
			if int64(len(data)) != wantSize {
				t.Errorf("part %d size was %d, want %d", part, len(data), wantSize)
			}
			uploadedParts++
			writer.Header().Set("ETag", fmt.Sprintf("multipart-etag-%d", part))
			return
		}

		checkSignedRequest(t, request, "sign-key")
		switch request.URL.Path {
		case "/open/v1/file/upload_pre":
			var body uploadPreRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("failed to decode multipart upload_pre request: %v", err)
			}
			if !body.HashUpdate || body.SHA1 != "" || body.MD5 != "" || body.PartInfo != nil {
				t.Errorf("unexpected multipart upload_pre body: %+v", body)
			}
			writeJSON(t, writer, map[string]any{"status": 0, "data": map[string]any{"task_id": "multipart-task", "part_size": partSize}})
		case "/open/v1/file/get_upload_urls":
			var body uploadURLsRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("failed to decode multipart URL request: %v", err)
			}
			part := body.PartInfo[0].PartNumber
			if part == 1 && body.PartInfo[0].SHA1 != nil {
				t.Errorf("first multipart part unexpectedly had a SHA1 context")
			}
			if part > 1 && (body.PartInfo[0].SHA1 == nil || body.PartInfo[0].SHA1.PartOffset != int64(part-1)*partSize) {
				t.Errorf("part %d had invalid SHA1 context: %+v", part, body.PartInfo[0].SHA1)
			}
			writeJSON(t, writer, map[string]any{"status": 0, "data": map[string]any{"upload_urls": []any{map[string]any{
				"part_number": part,
				"upload_url":  fmt.Sprintf("%s/multipart/%d", server.URL, part),
				"signature_info": map[string]string{
					"signature": fmt.Sprintf("signature-%d", part),
				},
			}}}})
		case "/open/v1/file/update/hash":
			if uploadedParts != 3 {
				t.Errorf("hash was updated after %d parts, want 3", uploadedParts)
			}
			var body map[string]string
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("failed to decode multipart hash request: %v", err)
			}
			md5sum := md5.Sum(content)
			sha1sum := sha1.Sum(content)
			if body["md5"] != hex.EncodeToString(md5sum[:]) || body["sha1"] != hex.EncodeToString(sha1sum[:]) {
				t.Errorf("unexpected multipart hashes: %+v", body)
			}
			writeJSON(t, writer, map[string]any{"status": 0, "data": map[string]any{"finish": false}})
		case "/open/v1/file/upload_finish":
			var body uploadFinishRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("failed to decode multipart finish request: %v", err)
			}
			if len(body.PartInfo) != 3 || body.PartInfo[2].ETag != "multipart-etag-3" {
				t.Errorf("unexpected multipart part list: %+v", body.PartInfo)
			}
			writeJSON(t, writer, map[string]any{"status": 0, "data": map[string]any{"finish": true, "fid": "multipart-fid"}})
		default:
			http.NotFound(writer, request)
		}
	})
	server = httptest.NewServer(handler)
	defer server.Close()
	f, _ := newTestFs(t, server)
	src := object.NewStaticObjectInfo("big.bin", time.Unix(123, 0), int64(len(content)), true, nil, f)

	obj, err := f.upload(context.Background(), bytes.NewReader(content), src, "big.bin", "parent-fid")
	require.NoError(t, err)
	assert.Equal(t, "multipart-fid", obj.ID())
	assert.Equal(t, 3, uploadedParts)
}

func TestExpiredTokenIsRotatedAndPersisted(t *testing.T) {
	var server *httptest.Server
	directoryCalls := 0
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/open/v1/dir":
			directoryCalls++
			if directoryCalls == 1 {
				writeJSON(t, writer, map[string]any{"status": 1, "errno": 11001, "error_info": "expired"})
				return
			}
			if request.URL.Query().Get("access_token") != "new-access" {
				t.Errorf("retried with access token %q", request.URL.Query().Get("access_token"))
			}
			writeJSON(t, writer, map[string]any{"status": 0, "data": map[string]any{"fid": "directory-fid"}})
		case "/agent/v1/oauth/access_token/rotate":
			var body map[string]string
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("failed to decode refresh request: %v", err)
			}
			if body["refresh_token"] != "refresh" || body["device_id"] != "device" {
				t.Errorf("unexpected refresh body: %+v", body)
			}
			writeJSON(t, writer, map[string]any{"status": 0, "data": map[string]any{"access_token": "new-access", "refresh_token": "new-refresh"}})
		default:
			http.NotFound(writer, request)
		}
	})
	server = httptest.NewServer(handler)
	defer server.Close()
	f, config := newTestFs(t, server)

	fid, err := f.CreateDir(context.Background(), "", "snapshot")
	require.NoError(t, err)
	assert.Equal(t, "directory-fid", fid)
	assert.Equal(t, 2, directoryCalls)
	accessToken, err := obscure.Reveal(config["access_token"])
	require.NoError(t, err)
	refreshToken, err := obscure.Reveal(config["refresh_token"])
	require.NoError(t, err)
	assert.Equal(t, "new-access", accessToken)
	assert.Equal(t, "new-refresh", refreshToken)
}

func TestSpoolInputRejectsChangedSourceSize(t *testing.T) {
	file, _, _, _, cleanup, err := spoolInput(strings.NewReader("short"), 10)
	assert.ErrorContains(t, err, "source size changed")
	assert.Nil(t, file)
	cleanup()
}

func TestAPIErrorWrapsOpenPlatformDetails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writeJSON(t, writer, map[string]any{"status": 1, "errno": 42, "agent_msg": "denied", "req_id": "request"})
	}))
	defer server.Close()
	f, _ := newTestFs(t, server)

	_, err := f.CreateDir(context.Background(), "", "snapshot")
	require.Error(t, err)
	assert.ErrorContains(t, err, "errno=42")
	assert.ErrorContains(t, err, "denied")
}
