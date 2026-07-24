package baidunetdisk

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/rclone/rclone/backend/baidunetdisk/api"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/lib/rest"
)

// chunkSize is the size of each chunk for upload (4MB as required by Baidu)
const chunkSize = 4 * 1024 * 1024

const emptyMD5 = "d41d8cd98f00b204e9800998ecf8427e"

type offsetReadSeeker struct {
	io.ReadSeeker
	base int64
}

func (r *offsetReadSeeker) Seek(offset int64, whence int) (int64, error) {
	if whence == io.SeekStart {
		offset += r.base
	}
	position, err := r.ReadSeeker.Seek(offset, whence)
	return position - r.base, err
}

// upload implements the two-pass upload flow for Baidu Netdisk
// Pass 1: Calculate chunk MD5 hashes (from source or temp file)
// Pass 2: Upload chunks after precreate
func (o *Object) upload(ctx context.Context, in io.Reader, size int64, options ...fs.OpenOption) error {
	if err := validatePath(o.remote); err != nil {
		return err
	}
	absPath := o.fs.absPath(o.remote)

	// Ensure parent directory exists
	parentDir := path.Dir(absPath)
	if err := o.fs.mkdir(ctx, parentDir); err != nil {
		return fmt.Errorf("failed to create parent directory: %w", err)
	}

	var reader io.ReadSeeker
	var tmpFile *os.File
	cleanupTempFile := func() {
		if tmpFile != nil {
			_ = tmpFile.Close()
			_ = os.Remove(tmpFile.Name())
		}
	}
	defer cleanupTempFile()

	if size < 0 {
		var err error
		tmpFile, err = os.CreateTemp("", "rclone-baidu-upload-*")
		if err != nil {
			return fmt.Errorf("failed to create temp file for unknown size upload: %w", err)
		}
		size, err = io.Copy(tmpFile, in)
		if err != nil {
			return fmt.Errorf("failed to spool unknown size upload: %w", err)
		}
		if _, err = tmpFile.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("failed to seek temp file: %w", err)
		}
		in = tmpFile
	}

	if size == 0 {
		return o.uploadWithHashes(ctx, bytes.NewReader(nil), absPath, 0, []string{emptyMD5})
	}

	if seeker, ok := in.(io.ReadSeeker); ok {
		if offset, err := seeker.Seek(0, io.SeekCurrent); err == nil {
			reader = &offsetReadSeeker{ReadSeeker: seeker, base: offset}
			fs.Debugf(o, "Using direct file access (seekable input)")
		}
	}

	if reader == nil {
		var err error
		tmpFile, err = os.CreateTemp("", "rclone-baidu-upload-*")
		if err != nil {
			return fmt.Errorf("failed to create temp file: %w", err)
		}

		blockList, err := o.spoolAndCalculateHashes(in, tmpFile, size)
		if err != nil {
			return fmt.Errorf("failed to spool file: %w", err)
		}

		if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("failed to seek temp file: %w", err)
		}
		reader = tmpFile

		return o.uploadWithHashes(ctx, reader, absPath, size, blockList)
	}

	blockList, err := o.calculateBlockHashes(reader, size)
	if err != nil {
		return fmt.Errorf("failed to calculate block hashes: %w", err)
	}

	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to start: %w", err)
	}

	return o.uploadWithHashes(ctx, reader, absPath, size, blockList)
}

// uploadWithHashes performs the upload with pre-calculated hashes
func (o *Object) uploadWithHashes(ctx context.Context, reader io.ReadSeeker, absPath string, size int64, blockList []string) error {
	// Precreate - check for rapid upload (秒传)
	precreateResp, err := o.precreate(ctx, absPath, size, blockList)
	if err != nil {
		return fmt.Errorf("precreate failed: %w", err)
	}

	// Check if rapid upload succeeded (return_type == 2)
	if precreateResp.ReturnType == 2 {
		fs.Debugf(o, "Rapid upload succeeded (秒传)")
		return o.refreshMetadata(ctx)
	}

	// Pass 2: Upload chunks
	uploadID := precreateResp.UploadID
	if uploadID == "" {
		return errors.New("no upload ID returned from precreate")
	}

	// Determine which blocks need to be uploaded
	blocksToUpload := precreateResp.BlockList
	if len(blocksToUpload) == 0 {
		// If empty, upload all blocks
		blocksToUpload = make([]int, len(blockList))
		for i := range blocksToUpload {
			blocksToUpload[i] = i
		}
	}

	// Upload each required block
	for _, blockIdx := range blocksToUpload {
		if blockIdx < 0 || blockIdx >= len(blockList) {
			return fmt.Errorf("precreate returned invalid block index %d for %d blocks", blockIdx, len(blockList))
		}
		if err := o.uploadBlock(ctx, reader, absPath, uploadID, blockIdx, size); err != nil {
			return fmt.Errorf("failed to upload block %d: %w", blockIdx, err)
		}
	}

	// Create/finalize the file
	if err := o.create(ctx, absPath, size, uploadID, blockList); err != nil {
		return fmt.Errorf("create failed: %w", err)
	}

	// Refresh metadata
	return o.refreshMetadata(ctx)
}

// calculateBlockHashes reads the entire file and calculates MD5 for each 4MB chunk
// Used when input is seekable (e.g., local file) - file is read twice but no temp file needed
func (o *Object) calculateBlockHashes(in io.Reader, size int64) ([]string, error) {
	if size < 0 {
		return nil, errors.New("cannot calculate hashes for an unknown size")
	}
	numBlocks := (size + chunkSize - 1) / chunkSize
	blockList := make([]string, 0, numBlocks)

	buf := make([]byte, chunkSize)
	remaining := size
	for remaining > 0 {
		toRead := min(remaining, int64(chunkSize))
		n, err := io.ReadFull(in, buf[:toRead])
		if err != nil {
			return nil, fmt.Errorf("read %d of %d declared bytes: %w", size-remaining+int64(n), size, err)
		}

		hash := md5.Sum(buf[:n])
		blockList = append(blockList, hex.EncodeToString(hash[:]))
		remaining -= int64(n)
	}

	return blockList, nil
}

// spoolAndCalculateHashes reads from input, writes to temp file, and calculates MD5 hashes
// for each 4MB chunk in a single pass (memory-efficient for non-seekable inputs)
func (o *Object) spoolAndCalculateHashes(in io.Reader, out io.Writer, size int64) ([]string, error) {
	numBlocks := (size + chunkSize - 1) / chunkSize
	blockList := make([]string, 0, numBlocks)

	buf := make([]byte, chunkSize)
	totalRead := int64(0)

	for totalRead < size {
		// Calculate how much to read for this chunk
		remaining := size - totalRead
		toRead := int64(chunkSize)
		if remaining < toRead {
			toRead = remaining
		}

		// Read chunk
		n, err := io.ReadFull(in, buf[:toRead])
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			return nil, fmt.Errorf("read error at offset %d: %w", totalRead, err)
		}
		if n == 0 {
			break
		}

		// Write to temp file
		if _, err := out.Write(buf[:n]); err != nil {
			return nil, fmt.Errorf("write error at offset %d: %w", totalRead, err)
		}

		// Calculate MD5 hash for this chunk
		hash := md5.Sum(buf[:n])
		blockList = append(blockList, hex.EncodeToString(hash[:]))

		totalRead += int64(n)
	}

	if totalRead != size {
		return nil, fmt.Errorf("size mismatch: expected %d bytes, got %d", size, totalRead)
	}

	return blockList, nil
}

// precreate sends the precreate request to Baidu API
func (o *Object) precreate(ctx context.Context, absPath string, size int64, blockList []string) (*api.PrecreateResponse, error) {
	blockListJSON, err := json.Marshal(blockList)
	if err != nil {
		return nil, err
	}

	params := url.Values{
		"method": {"precreate"},
	}
	if err := o.fs.addToken(params); err != nil {
		return nil, err
	}

	form := url.Values{
		"path":       {absPath},
		"size":       {strconv.FormatInt(size, 10)},
		"isdir":      {"0"},
		"autoinit":   {"1"},
		"block_list": {string(blockListJSON)},
		"rtype":      {"2"}, // overwrite if the path exists
	}

	opts := rest.Opts{
		Method:      "POST",
		Path:        "/rest/2.0/xpan/file",
		ContentType: "application/x-www-form-urlencoded",
		Parameters:  params,
		Body:        strings.NewReader(form.Encode()),
	}

	var result api.PrecreateResponse
	err = o.fs.callJSON(ctx, &opts, &result, &result.Errno)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// uploadBlock uploads a single block to Baidu
func (o *Object) uploadBlock(ctx context.Context, in io.ReadSeeker, absPath, uploadID string, blockIdx int, totalSize int64) error {
	if blockIdx < 0 {
		return fmt.Errorf("invalid negative block index %d", blockIdx)
	}
	if totalSize < 0 {
		return fmt.Errorf("invalid negative file size %d", totalSize)
	}
	// Seek to the block position
	offset := int64(blockIdx) * chunkSize
	if totalSize == 0 && blockIdx != 0 {
		return fmt.Errorf("block index %d is outside an empty file", blockIdx)
	}
	if totalSize > 0 && offset >= totalSize {
		return fmt.Errorf("block index %d is outside file size %d", blockIdx, totalSize)
	}
	if _, err := in.Seek(offset, io.SeekStart); err != nil {
		return err
	}

	// Calculate block size
	blockSize := chunkSize
	remaining := totalSize - offset
	if remaining < int64(blockSize) {
		blockSize = int(remaining)
	}

	// Get access token
	token, err := o.fs.ts.Token()
	if err != nil {
		return fmt.Errorf("failed to get access token: %w", err)
	}

	// Build the multipart form
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "blob")
	if err != nil {
		return err
	}
	if _, err := io.CopyN(part, in, int64(blockSize)); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}

	uploadURL, err := url.Parse(uploadRootURL + "/rest/2.0/pcs/superfile2")
	if err != nil {
		return err
	}
	query := uploadURL.Query()
	query.Set("method", "upload")
	query.Set("access_token", token.AccessToken)
	query.Set("type", "tmpfile")
	query.Set("path", absPath)
	query.Set("uploadid", uploadID)
	query.Set("partseq", strconv.Itoa(blockIdx))
	uploadURL.RawQuery = query.Encode()

	bodyData := append([]byte(nil), body.Bytes()...)
	contentType := writer.FormDataContentType()
	err = o.fs.pacer.Call(func() (bool, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL.String(), bytes.NewReader(bodyData))
		if err != nil {
			return false, err
		}
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("User-Agent", baiduUserAgent)

		resp, err := o.fs.client.Do(req)
		if err != nil {
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
			return shouldRetry(ctx, resp, err)
		}
		if resp.StatusCode >= http.StatusBadRequest {
			err = errorHandler(resp)
			return shouldRetry(ctx, resp, err)
		}

		var result api.SuperfileResponse
		decodeErr := json.NewDecoder(resp.Body).Decode(&result)
		closeErr := resp.Body.Close()
		if decodeErr != nil {
			err = fmt.Errorf("failed to decode upload response: %w", decodeErr)
		} else if closeErr != nil {
			err = closeErr
		} else if result.Errno != api.ErrnoSuccess {
			err = &api.Error{Errno: result.Errno}
		}
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return err
	}

	fs.Debugf(o, "Uploaded block %d", blockIdx)
	return nil
}

// create finalizes the upload by calling the create API
func (o *Object) create(ctx context.Context, absPath string, size int64, uploadID string, blockList []string) error {
	blockListJSON, err := json.Marshal(blockList)
	if err != nil {
		return err
	}

	params := url.Values{
		"method": {"create"},
	}
	if err := o.fs.addToken(params); err != nil {
		return err
	}

	form := url.Values{
		"path":       {absPath},
		"size":       {strconv.FormatInt(size, 10)},
		"isdir":      {"0"},
		"uploadid":   {uploadID},
		"block_list": {string(blockListJSON)},
		"rtype":      {"2"}, // overwrite if the path exists
	}

	opts := rest.Opts{
		Method:      "POST",
		Path:        "/rest/2.0/xpan/file",
		ContentType: "application/x-www-form-urlencoded",
		Parameters:  params,
		Body:        strings.NewReader(form.Encode()),
	}

	var result api.CreateResponse
	err = o.fs.callJSON(ctx, &opts, &result, &result.Errno)
	if err != nil {
		return err
	}

	// Update object metadata from create response
	o.fsID = result.FsID
	o.md5 = result.MD5
	o.size = result.Size
	o.modTime = result.Mtime.Time()
	o.path = result.Path

	return nil
}

// refreshMetadata refreshes the object's metadata from the server
func (o *Object) refreshMetadata(ctx context.Context) error {
	absPath := o.fs.absPath(o.remote)
	info, err := o.fs.getFileInfo(ctx, absPath)
	if err != nil {
		return err
	}

	o.fsID = info.FsID
	o.md5 = info.MD5
	o.size = info.Size
	o.modTime = info.ServerMtime.Time()
	o.path = info.Path

	return nil
}
