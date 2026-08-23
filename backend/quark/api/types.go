// Package api defines Quark Drive open-platform API types.
package api

import "fmt"

// Response contains fields shared by open-platform responses.
type Response struct {
	Status    int    `json:"status"`
	Errno     int    `json:"errno"`
	ErrorInfo string `json:"error_info"`
	AgentMsg  string `json:"agent_msg"`
	RequestID string `json:"req_id"`
}

// Check returns an error when the API did not report success.
func (r Response) Check() error {
	if r.Status == 0 && r.Errno == 0 {
		return nil
	}
	message := r.AgentMsg
	if message == "" {
		message = r.ErrorInfo
	}
	return &Error{Status: r.Status, Errno: r.Errno, Message: message, RequestID: r.RequestID}
}

// Error describes an open-platform API error.
type Error struct {
	Status    int
	Errno     int
	Message   string
	RequestID string
}

// Error returns a readable API error.
func (e *Error) Error() string {
	return fmt.Sprintf("quark open-platform error: status=%d errno=%d message=%q request_id=%q", e.Status, e.Errno, e.Message, e.RequestID)
}

// CreateDirResponse is returned after creating an idempotent directory.
type CreateDirResponse struct {
	Response
	Data struct {
		FID string `json:"fid"`
	} `json:"data"`
}

// UploadURL describes one pre-authorized object-storage part URL.
type UploadURL struct {
	PartNumber    int    `json:"part_number"`
	UploadURL     string `json:"upload_url"`
	SignatureInfo struct {
		Signature string `json:"signature"`
	} `json:"signature_info"`
}

// UploadPreResponse describes an initialized upload task.
type UploadPreResponse struct {
	Response
	Data struct {
		TaskID        string            `json:"task_id"`
		PartSize      int64             `json:"part_size"`
		Finish        bool              `json:"finish"`
		FID           string            `json:"fid"`
		UploadURLs    []UploadURL       `json:"upload_urls"`
		CommonHeaders map[string]string `json:"common_headers"`
	} `json:"data"`
}

// UploadURLsResponse contains URLs for requested multipart sections.
type UploadURLsResponse struct {
	Response
	Data struct {
		UploadURLs    []UploadURL       `json:"upload_urls"`
		CommonHeaders map[string]string `json:"common_headers"`
	} `json:"data"`
}

// UploadHashResponse reports the result of attaching content hashes.
type UploadHashResponse struct {
	Response
	Data struct {
		Finish bool   `json:"finish"`
		FID    string `json:"fid"`
	} `json:"data"`
}

// UploadFinishResponse reports the completed upload.
type UploadFinishResponse struct {
	Response
	Data struct {
		Finish bool   `json:"finish"`
		FID    string `json:"fid"`
	} `json:"data"`
}

// MoveResponse describes a file move operation.
type MoveResponse struct {
	Response
	Data struct {
		Finish bool   `json:"finish"`
		TaskID string `json:"task_id"`
	} `json:"data"`
}

// QueryTaskResponse describes the state of an asynchronous file operation.
type QueryTaskResponse struct {
	Response
	Data struct {
		Status int `json:"status"`
	} `json:"data"`
}

// RotateTokenResponse contains refreshed long-lived credentials.
type RotateTokenResponse struct {
	Response
	Data struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	} `json:"data"`
}
