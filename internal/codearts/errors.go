package codearts

import (
	"errors"
	"fmt"
)

var (
	ErrDisabled    = errors.New("CodeArts 出口未启用")
	ErrNoAccount   = errors.New("没有可用的 CodeArts 账号")
	ErrBusy        = errors.New("CodeArts 账号正忙")
	ErrAuth        = errors.New("CodeArts 授权失败")
	ErrBadRequest  = errors.New("CodeArts 请求参数错误")
	ErrUnavailable = errors.New("CodeArts 上游不可用")
	ErrUpstream    = errors.New("CodeArts 上游错误")
)

// APIError carries an HTTP status and an actionable message. The server maps
// it to an OpenAI-compatible error body; it never contains credentials.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e == nil {
		return ""
	}
	if e.Code != "" {
		return fmt.Sprintf("CodeArts [%s]: %s", e.Code, e.Message)
	}
	return "CodeArts: " + e.Message
}

func (e *APIError) Unwrap() error {
	switch e.Status {
	case 400:
		return ErrBadRequest
	case 401, 403:
		return ErrAuth
	case 409:
		return ErrBusy
	case 429:
		return ErrBusy
	case 503:
		return ErrUnavailable
	}
	return ErrUpstream
}

// asAPIError converts any error into an APIError with a sensible status.
func asAPIError(err error) *APIError {
	if err == nil {
		return nil
	}
	var ae *APIError
	if errors.As(err, &ae) {
		return ae
	}
	switch {
	case errors.Is(err, ErrDisabled):
		return &APIError{Status: 403, Code: "codearts_disabled", Message: err.Error()}
	case errors.Is(err, ErrNoAccount):
		return &APIError{Status: 503, Code: "codearts_no_account", Message: err.Error()}
	case errors.Is(err, ErrBusy):
		return &APIError{Status: 429, Code: "codearts_busy", Message: err.Error()}
	case errors.Is(err, ErrAuth):
		return &APIError{Status: 401, Code: "codearts_auth", Message: err.Error()}
	case errors.Is(err, ErrBadRequest):
		return &APIError{Status: 400, Code: "codearts_bad_request", Message: err.Error()}
	case errors.Is(err, ErrUnavailable):
		return &APIError{Status: 503, Code: "codearts_unavailable", Message: err.Error()}
	default:
		return &APIError{Status: 502, Code: "codearts_upstream", Message: err.Error()}
	}
}
