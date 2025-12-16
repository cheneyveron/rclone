package baidunetdisk

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
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

// upload implements the two-pass upload flow for Baidu Netdisk
// Pass 1: Calculate chunk MD5 hashes (from source or temp file)
// Pass 2: Upload chunks after precreate
func (o *Object) upload(ctx context.Context, in io.Reader, size int64, options ...fs.OpenOption) error {
	absPath := o.fs.absPath(o.remote)

	// Ensure parent directory exists
	parentDir := path.Dir(absPath)
	if err := o.fs.mkdir(ctx, parentDir); err != nil {
		return fmt.Errorf("failed to create parent directory: %w", err)
	}

	// Handle empty file
	if size == 0 {
		return o.uploadEmpty(ctx, absPath)
	}

	// Check if input supports seeking (e.g., local file)
	// If so, we can read directly without temp file (more efficient)
	var reader io.ReadSeeker
	var tmpFile *os.File
	useDirectAccess := false

	if seeker, ok := in.(io.ReadSeeker); ok {
		// Test if seeking actually works (asyncreader.AsyncReader implements
		// io.Seeker but returns error when called)
		if _, err := seeker.Seek(0, io.SeekCurrent); err == nil {
			// Input is truly seekable - use it directly
			reader = seeker
			useDirectAccess = true
			fs.Debugf(o, "Using direct file access (seekable input)")
		}
	}

	if !useDirectAccess {
		// Input is not seekable (async reader, stream, etc.)
		// Spool to temp file
		var err error
		tmpFile, err = os.CreateTemp("", "rclone-baidu-upload-*")
		if err != nil {
			return fmt.Errorf("failed to create temp file: %w", err)
		}
		defer func() {
			_ = tmpFile.Close()
			_ = os.Remove(tmpFile.Name())
		}()

		// Copy input to temp file while calculating hashes
		blockList, err := o.spoolAndCalculateHashes(in, tmpFile, size)
		if err != nil {
			return fmt.Errorf("failed to spool file: %w", err)
		}

		// Reset temp file for reading
		if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("failed to seek temp file: %w", err)
		}
		reader = tmpFile

		// Skip hash calculation below - we already have blockList
		return o.uploadWithHashes(ctx, reader, absPath, size, blockList)
	}

	// For seekable input: calculate hashes first, then upload
	blockList, err := o.calculateBlockHashes(reader, size)
	if err != nil {
		return fmt.Errorf("failed to calculate block hashes: %w", err)
	}

	// Reset to beginning for upload
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
		return fmt.Errorf("no upload ID returned from precreate")
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
	numBlocks := (size + chunkSize - 1) / chunkSize
	blockList := make([]string, 0, numBlocks)

	buf := make([]byte, chunkSize)
	for {
		n, err := io.ReadFull(in, buf)
		if err == io.EOF {
			break
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			return nil, err
		}

		hash := md5.Sum(buf[:n])
		blockList = append(blockList, hex.EncodeToString(hash[:]))

		if err == io.ErrUnexpectedEOF {
			break
		}
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
		"rtype":      {"3"}, // 3 = overwrite if exists
	}

	opts := rest.Opts{
		Method:      "POST",
		Path:        "/rest/2.0/xpan/file",
		ContentType: "application/x-www-form-urlencoded",
		Parameters:  params,
		Body:        strings.NewReader(form.Encode()),
	}

	var result api.PrecreateResponse
	var resp *http.Response
	err = o.fs.pacer.Call(func() (bool, error) {
		resp, err = o.fs.srv.CallJSON(ctx, &opts, nil, &result)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return nil, err
	}
	if result.Errno != 0 {
		return nil, &api.Error{Errno: result.Errno}
	}

	return &result, nil
}

// uploadBlock uploads a single block to Baidu
func (o *Object) uploadBlock(ctx context.Context, in io.ReadSeeker, absPath, uploadID string, blockIdx int, totalSize int64) error {
	// Seek to the block position
	offset := int64(blockIdx) * chunkSize
	if _, err := in.Seek(offset, io.SeekStart); err != nil {
		return err
	}

	// Calculate block size
	blockSize := chunkSize
	remaining := totalSize - offset
	if remaining < int64(blockSize) {
		blockSize = int(remaining)
	}

	// Read the block
	blockData := make([]byte, blockSize)
	if _, err := io.ReadFull(in, blockData); err != nil {
		return err
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
	if _, err := part.Write(blockData); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}

	// Build URL with parameters
	uploadURL := fmt.Sprintf("%s/rest/2.0/pcs/superfile2?method=upload&access_token=%s&type=tmpfile&path=%s&uploadid=%s&partseq=%d",
		uploadRootURL,
		url.QueryEscape(token.AccessToken),
		url.QueryEscape(absPath),
		url.QueryEscape(uploadID),
		blockIdx,
	)

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", uploadURL, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("User-Agent", baiduUserAgent)

	// Execute request
	var resp *http.Response
	err = o.fs.pacer.Call(func() (bool, error) {
		resp, err = o.fs.client.Do(req)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	// Parse response
	var result api.SuperfileResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode upload response: %w", err)
	}
	if result.Errno != 0 {
		return &api.Error{Errno: result.Errno}
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
		"rtype":      {"3"}, // 3 = overwrite if exists
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
	err = o.fs.pacer.Call(func() (bool, error) {
		resp, err = o.fs.srv.CallJSON(ctx, &opts, nil, &result)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return err
	}
	if result.Errno != 0 {
		return &api.Error{Errno: result.Errno}
	}

	// Update object metadata from create response
	o.fsID = result.FsID
	o.md5 = result.MD5
	o.size = result.Size
	o.modTime = result.Mtime.Time()
	o.path = result.Path

	return nil
}

// uploadEmpty handles empty file upload
func (o *Object) uploadEmpty(ctx context.Context, absPath string) error {
	// For empty files, we can use create directly with empty block list
	blockListJSON, _ := json.Marshal([]string{"d41d8cd98f00b204e9800998ecf8427e"}) // MD5 of empty content

	params := url.Values{
		"method": {"create"},
	}
	if err := o.fs.addToken(params); err != nil {
		return err
	}

	form := url.Values{
		"path":       {absPath},
		"size":       {"0"},
		"isdir":      {"0"},
		"block_list": {string(blockListJSON)},
		"rtype":      {"3"}, // 3 = overwrite if exists
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
	err = o.fs.pacer.Call(func() (bool, error) {
		resp, err = o.fs.srv.CallJSON(ctx, &opts, nil, &result)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return err
	}
	if result.Errno != 0 {
		return &api.Error{Errno: result.Errno}
	}

	// Update object metadata
	o.fsID = result.FsID
	o.md5 = result.MD5
	o.size = 0
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
