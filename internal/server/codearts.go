package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"

	"github.com/misakano7545/workbuddy2api-panel/internal/codearts"
)

// isCodeArtsRequest reports whether this chat request targets the CodeArts
// egress. The realm can be selected by the `realm=codearts` query (used by
// /v1/models?realm=codearts) or by a `codearts:` model prefix.
func (h *Handler) isCodeArtsRequest(r *http.Request, model string) bool {
	if h == nil || h.cfg.CodeArts == nil {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("realm")), "codearts") {
		return true
	}
	return strings.HasPrefix(strings.TrimSpace(model), "codearts:")
}

func (h *Handler) codeartsModelEntries(prefixed bool) []map[string]any {
	if h.cfg.CodeArts == nil || !h.cfg.CodeArts.Enabled() {
		return nil
	}
	models := h.cfg.CodeArts.Models(context.Background())
	out := make([]map[string]any, 0, len(models))
	for _, mi := range models {
		id := mi.ID
		if prefixed {
			id = "codearts:" + id
		}
		entry := map[string]any{
			"id":       id,
			"object":   "model",
			"created":  1753600000,
			"owned_by": "codearts",
		}
		if mi.Name != "" {
			entry["name"] = mi.Name
		}
		if mi.ContextWindow > 0 {
			entry["context_length"] = mi.ContextWindow
		}
		if mi.MaxTokens > 0 {
			entry["max_output_tokens"] = mi.MaxTokens
		}
		if mi.Description != "" {
			entry["description"] = mi.Description
		}
		if mi.Credits != "" {
			entry["credits"] = mi.Credits
		}
		if mi.Benefit {
			entry["benefit"] = true
		}
		if mi.SupportsImages != nil {
			entry["supports_images"] = *mi.SupportsImages
		}
		out = append(out, entry)
	}
	return out
}

// codeartsChat handles an OpenAI chat completion against CodeArts. The caller
// already authenticated the gateway API key.
func (h *Handler) codeartsChat(w http.ResponseWriter, r *http.Request, body []byte, model string, stream bool) {
	if h.cfg.CodeArts == nil {
		writeOpenAIError(w, http.StatusServiceUnavailable, "codearts_unavailable",
			"CodeArts is not configured")
		return
	}
	model = strings.TrimPrefix(strings.TrimSpace(model), "codearts:")
	cs, _, err := h.cfg.CodeArts.OpenChat(r.Context(), model, body)
	if err != nil {
		writeCodeArtsError(w, err)
		return
	}
	defer cs.Close()

	if !stream {
		obj, err := cs.Aggregate()
		if err != nil {
			writeCodeArtsError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, obj)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher, _ := w.(http.Flusher)
	w.WriteHeader(http.StatusOK)
	for {
		chunk, err := cs.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// The status line is already committed; report the failure inside
			// the stream as an OpenAI error frame, then terminate.
			writeSSEErrorFrame(w, err)
			if flusher != nil {
				flusher.Flush()
			}
			return
		}
		if len(chunk) == 0 {
			continue
		}
		if _, err := w.Write(chunk); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

func writeSSEErrorFrame(w http.ResponseWriter, err error) {
	msg := err.Error()
	code := "codearts_error"
	var ae *codearts.APIError
	if errors.As(err, &ae) {
		code, msg = ae.Code, ae.Message
	}
	payload := map[string]any{
		"error": map[string]any{
			"message": msg,
			"type":    "codearts_error",
			"code":    code,
		},
	}
	raw, _ := json.Marshal(payload)
	_, _ = w.Write([]byte("data: " + string(raw) + "\n\ndata: [DONE]\n\n"))
}

// codeartsOAuthCallback is the public browser callback. It resolves the
// registered OAuth session, exchanges the code and renders a small result page.
func (h *Handler) codeartsOAuthCallback(w http.ResponseWriter, r *http.Request) {
	if h.cfg.CodeArts == nil {
		http.Error(w, "CodeArts is not configured", http.StatusNotFound)
		return
	}
	host := r.Host
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	raw := fmt.Sprintf("%s://%s%s", scheme, host, r.URL.RequestURI())
	status, err := h.cfg.CodeArts.OAuthCallbackURL(raw)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "<!doctype html><meta charset=utf-8><title>CodeArts 授权失败</title><p>授权失败：%s</p>", html.EscapeString(err.Error()))
		return
	}
	if status != nil && status.Status == "done" {
		fmt.Fprintf(w, "<!doctype html><meta charset=utf-8><title>CodeArts 授权成功</title><p>授权成功：%s（%s）。可以关闭此页面，回到网关面板刷新账号。</p>", html.EscapeString(status.Nickname), html.EscapeString(status.UID))
		return
	}
	fmt.Fprint(w, "<!doctype html><meta charset=utf-8><title>CodeArts 授权</title><p>已收到回调，正在等待授权完成。可以回到网关面板查看状态。</p>")
}

func writeCodeArtsError(w http.ResponseWriter, err error) {
	if err == nil {
		err = codearts.ErrUpstream
	}
	status := http.StatusBadGateway
	code := "codearts_error"
	msg := err.Error()
	var ae *codearts.APIError
	if errors.As(err, &ae) {
		status, code, msg = ae.Status, ae.Code, ae.Message
	} else {
		switch {
		case errors.Is(err, codearts.ErrDisabled):
			status, code = http.StatusForbidden, "codearts_disabled"
		case errors.Is(err, codearts.ErrNoAccount):
			status, code = http.StatusServiceUnavailable, "codearts_no_account"
		case errors.Is(err, codearts.ErrBusy):
			status, code = http.StatusTooManyRequests, "codearts_busy"
		case errors.Is(err, codearts.ErrAuth):
			status, code = http.StatusUnauthorized, "codearts_auth"
		case errors.Is(err, codearts.ErrBadRequest):
			status, code = http.StatusBadRequest, "codearts_bad_request"
		case errors.Is(err, codearts.ErrUnavailable):
			status, code = http.StatusServiceUnavailable, "codearts_unavailable"
		}
	}
	if status < 400 || status > 599 {
		status = http.StatusBadGateway
	}
	writeOpenAIErrorHint(w, status, code, msg, "CodeArts egress")
}
