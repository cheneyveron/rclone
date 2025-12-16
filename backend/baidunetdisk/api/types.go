// Package api has type definitions for Baidu Netdisk (xPan)
package api

import (
	"fmt"
	"time"
)

// Error represents API error from Baidu Netdisk
type Error struct {
	Errno     int    `json:"errno"`
	ErrMsg    string `json:"errmsg,omitempty"`
	RequestID int64  `json:"request_id,omitempty"`
}

// Error returns a string for the error and satisfies the error interface
func (e *Error) Error() string {
	return fmt.Sprintf("baidu: api error %d: %s", e.Errno, e.ErrMsg)
}

// Check Error satisfies the error interface
var _ error = (*Error)(nil)

// Common API error codes
const (
	// Success
	ErrnoSuccess = 0

	// Authentication errors
	ErrnoAccessTokenInvalid  = 110   // Access token invalid or expired
	ErrnoAccessTokenExpired  = 111   // Access token expired
	ErrnoRefreshTokenInvalid = 31045 // Refresh token invalid
	ErrnoUserNotAuthorized   = -6    // User not authorized, app access denied (check app_name matches your registered Baidu app)

	// File errors
	ErrnoFileNotExist       = -9    // File does not exist
	ErrnoFileAlreadyExist   = 31061 // File already exists
	ErrnoFileAlreadyExist2  = -8    // File already exists (alternate code)
	ErrnoInsufficientSpace  = 31202 // Insufficient storage space
	ErrnoPathNotExist       = -7    // Path does not exist
	ErrnoFileNameInvalid    = 31062 // Invalid file name
	ErrnoFileTooLarge       = 31066 // File too large
	ErrnoUploadIDNotExist   = 31363 // Upload ID does not exist or has expired
	ErrnoBlockMD5NotMatch   = 31364 // Block MD5 mismatch
	ErrnoBlockSizeError     = 31365 // Block size error
	ErrnoBlockSeqError      = 31366 // Block sequence error
	ErrnoDirNotEmpty        = 31066 // Directory not empty
	ErrnoTaskNotFound       = 12    // Async task not found
	ErrnoRapidUploadFailed  = -7    // Rapid upload (秒传) failed, need full upload
	ErrnoPrecreateBlockHash = 31190 // precreate returns this when block_list hash format is incorrect
)

// Time represents Unix timestamp from Baidu API
type Time int64

// Time returns time.Time
func (t Time) Time() time.Time {
	return time.Unix(int64(t), 0)
}

// File represents a file or folder in Baidu Netdisk
type File struct {
	FsID           int64  `json:"fs_id"`
	Path           string `json:"path"`
	ServerFilename string `json:"server_filename"`
	Size           int64  `json:"size"`
	ServerMtime    Time   `json:"server_mtime"`
	ServerCtime    Time   `json:"server_ctime"`
	LocalMtime     Time   `json:"local_mtime"`
	LocalCtime     Time   `json:"local_ctime"`
	IsDir          int    `json:"isdir"`
	Category       int    `json:"category"`
	MD5            string `json:"md5,omitempty"`
	DirEmpty       int    `json:"dir_empty,omitempty"`
	Thumbs         Thumbs `json:"thumbs,omitempty"`
	// Additional fields for filemetas
	DLink    string `json:"dlink,omitempty"`
	Filename string `json:"filename,omitempty"`
}

// Thumbs contains thumbnail URLs
type Thumbs struct {
	URL1 string `json:"url1,omitempty"`
	URL2 string `json:"url2,omitempty"`
	URL3 string `json:"url3,omitempty"`
}

// ListResponse is the response from list API
type ListResponse struct {
	Errno    int     `json:"errno"`
	GuidInfo string  `json:"guid_info,omitempty"`
	List     []*File `json:"list"`
	HasMore  int     `json:"has_more,omitempty"` // 0 = no more, 1 = has more (only for some APIs)
}

// FileMetasRequest is the request for filemetas API
type FileMetasRequest struct {
	FsIDs []int64 `json:"fsids"`
	DLink int     `json:"dlink"` // 1 = include download link
}

// FileMetasResponse is the response from filemetas API
type FileMetasResponse struct {
	Errno int     `json:"errno"`
	List  []*File `json:"list"`
}

// PrecreateRequest is the request for precreate API
type PrecreateRequest struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	IsDir     int    `json:"isdir"`
	AutoInit  int    `json:"autoinit"`
	BlockList string `json:"block_list"` // JSON array of MD5 hashes
	RType     int    `json:"rtype"`      // 0=default, 1=rename if exists, 2=rename with path, 3=overwrite
}

// PrecreateResponse is the response from precreate API
type PrecreateResponse struct {
	Errno      int    `json:"errno"`
	Path       string `json:"path"`
	UploadID   string `json:"uploadid,omitempty"`
	ReturnType int    `json:"return_type"` // 1=need upload, 2=rapid upload success
	BlockList  []int  `json:"block_list"`  // indexes of blocks that need to be uploaded
}

// SuperfileResponse is the response from superfile2 upload API
type SuperfileResponse struct {
	Errno     int    `json:"errno"`
	MD5       string `json:"md5,omitempty"`
	RequestID int64  `json:"request_id,omitempty"`
}

// CreateRequest is the request for create API (finalize upload)
type CreateRequest struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	IsDir     int    `json:"isdir"`
	UploadID  string `json:"uploadid"`
	BlockList string `json:"block_list"` // JSON array of MD5 hashes
	RType     int    `json:"rtype"`      // 0=default, 1=rename if exists, 2=rename with path, 3=overwrite
}

// CreateResponse is the response from create API
type CreateResponse struct {
	Errno      int    `json:"errno"`
	FsID       int64  `json:"fs_id"`
	MD5        string `json:"md5,omitempty"`
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	Ctime      Time   `json:"ctime"`
	Mtime      Time   `json:"mtime"`
	IsDir      int    `json:"isdir"`
	Name       string `json:"name,omitempty"`
	Category   int    `json:"category,omitempty"`
	ServerPath string `json:"server_path,omitempty"`
}

// FileManagerOp represents file manager operation type
type FileManagerOp string

const (
	FileManagerOpCopy   FileManagerOp = "copy"
	FileManagerOpMove   FileManagerOp = "move"
	FileManagerOpRename FileManagerOp = "rename"
	FileManagerOpDelete FileManagerOp = "delete"
)

// FileManagerItem represents an item in filemanager request
type FileManagerItem struct {
	Path    string `json:"path"`
	Dest    string `json:"dest,omitempty"`    // destination directory for copy/move
	NewName string `json:"newname,omitempty"` // new name for rename/copy/move
}

// FileManagerResponse is the response from filemanager API
type FileManagerResponse struct {
	Errno  int           `json:"errno"`
	Info   []*FileOpInfo `json:"info,omitempty"`
	TaskID int64         `json:"taskid,omitempty"` // for async operations
}

// FileOpInfo contains result of file operation
type FileOpInfo struct {
	Errno int    `json:"errno"`
	Path  string `json:"path"`
}

// TaskQueryResponse is the response from task query API
type TaskQueryResponse struct {
	Errno  int    `json:"errno"`
	TaskID int64  `json:"task_id,omitempty"`
	Status string `json:"status,omitempty"` // pending, running, success, failed
	List   []*struct {
		Path string `json:"path"`
	} `json:"list,omitempty"`
}

// QuotaResponse is the response from quota API
type QuotaResponse struct {
	Errno  int   `json:"errno"`
	Total  int64 `json:"total"`
	Expire bool  `json:"expire,omitempty"`
	Used   int64 `json:"used"`
	Free   int64 `json:"free"`
}

// UserInfoResponse is the response from user info API
type UserInfoResponse struct {
	Errno       int    `json:"errno"`
	BaiduName   string `json:"baidu_name,omitempty"`
	NetdiskName string `json:"netdisk_name,omitempty"`
	AvatarURL   string `json:"avatar_url,omitempty"`
	VipType     int    `json:"vip_type,omitempty"` // 0=normal, 1=VIP, 2=SVIP
	UK          int64  `json:"uk,omitempty"`
}
