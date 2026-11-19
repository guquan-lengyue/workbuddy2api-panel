package codearts

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultModel     = "GLM-5.2"
	maxChatBody      = 64 << 20
	maxErrorBody     = 256 << 10
	receiveTimestamp = 1753600000
)

// OpenChat selects an account, refreshes credentials, builds the upstream body
// and returns a streaming reader of OpenAI-compatible chunks.
func (m *Manager) OpenChat(ctx context.Context, model string, body []byte) (*ChatStream, *Account, error) {
	if m == nil || !m.Enabled() {
		return nil, nil, ErrDisabled
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, nil, &APIError{Status: 400, Code: "invalid_request", Message: "请求体不是合法 JSON：" + err.Error()}
	}
	model = strings.TrimSpace(model)
	if model == "" {
		if s, _ := payload["model"].(string); s != "" {
			model = s
		}
	}
	model = strings.TrimPrefix(model, "codearts:")
	if model == "" {
		model = defaultModel
	}

	m.mu.RLock()
	accountCount := len(m.accounts)
	m.mu.RUnlock()
	exclude := map[string]bool{}
	attempts := accountCount + 2
	if attempts < 3 {
		attempts = 3
	}
	waitDeadline := time.Now().Add(time.Duration(m.Config().BusyWaitSeconds * float64(time.Second)))
	var lastErr error
	for i := 0; i < attempts; i++ {
		a := m.pick(model, exclude)
		if a == nil {
			busy := m.busyAccounts(exclude)
			if len(busy) > 0 && time.Now().Before(waitDeadline) {
				time.Sleep(200 * time.Millisecond)
				i--
				if i < -1 {
					i = -1
				}
				continue
			}
			if len(exclude) > 0 {
				break
			}
			return nil, nil, ErrNoAccount
		}
		if !a.acquire(m.Config().MaxConcurrent) {
			exclude[a.UserID] = true
			continue
		}
		if err := ensureToken(ctx, m, a); err != nil {
			a.release()
			exclude[a.UserID] = true
			lastErr = err
			continue
		}
		m.ensureModels(ctx, a, false)
		canonical := a.canonicalModel(model)
		upstreamBody, err := buildChatBody(payload, canonical, a)
		if err != nil {
			a.release()
			return nil, nil, err
		}
		stream, apiErr := m.openStream(ctx, a, canonical, upstreamBody)
		if apiErr != nil {
			a.release()
			if errors.Is(apiErr, ErrAuth) {
				m.NoteAccountError(a.UserID, apiErr.Error(), false, true, 0)
				exclude[a.UserID] = true
				lastErr = apiErr
				continue
			}
			if errors.Is(apiErr, ErrBusy) {
				m.NoteAccountError(a.UserID, apiErr.Error(), true, false, 0)
				exclude[a.UserID] = true
				lastErr = apiErr
				continue
			}
			if errors.Is(apiErr, ErrBadRequest) {
				return nil, nil, apiErr
			}
			m.NoteAccountError(a.UserID, apiErr.Error(), true, false, 0)
			exclude[a.UserID] = true
			lastErr = apiErr
			continue
		}
		m.NoteAccountSuccess(a.UserID)
		return stream, a, nil
	}
	if lastErr != nil {
		return nil, nil, lastErr
	}
	return nil, nil, ErrNoAccount
}

func buildChatBody(payload map[string]any, model string, a *Account) ([]byte, error) {
	allowed := map[string]bool{
		"model": true, "messages": true, "temperature": true, "top_p": true,
		"max_tokens": true, "max_completion_tokens": true, "reasoning_effort": true,
		"tools": true, "tool_choice": true, "stop": true,
		"frequency_penalty": true, "presence_penalty": true, "seed": true,
		"response_format": true, "top_k": true, "parallel_tool_calls": true,
	}
	out := map[string]any{}
	for k, v := range payload {
		if allowed[k] {
			out[k] = v
		}
	}
	msgs, _ := out["messages"].([]any)
	if len(msgs) == 0 {
		return nil, &APIError{Status: 400, Code: "messages_empty", Message: "messages is empty"}
	}
	if out["max_completion_tokens"] != nil && out["max_tokens"] == nil {
		out["max_tokens"] = out["max_completion_tokens"]
	}
	delete(out, "max_completion_tokens")
	out["model"] = model
	if v, ok := out["max_tokens"]; ok && v != nil {
		if n, ok := numberToInt64(v); ok {
			if limit := a.outputLimit(model); limit > 0 && n > limit {
				out["max_tokens"] = limit
			}
			if n <= 0 {
				return nil, &APIError{Status: 400, Code: "bad_max_tokens", Message: "max_tokens must be a positive integer"}
			}
		} else {
			return nil, &APIError{Status: 400, Code: "bad_max_tokens", Message: "max_tokens must be a positive integer"}
		}
	}
	chatID := ""
	if s, _ := payload["conversation_id"].(string); validChatID(s) {
		chatID = s
	}
	if chatID == "" {
		chatID = deriveChatID(msgs)
	}
	out["chat_id"] = chatID
	out["prompt_cache_key"] = chatID
	out["stream"] = true
	out["tool_stream"] = true
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func numberToInt64(v any) (int64, bool) {
	switch t := v.(type) {
	case float64:
		return int64(t), true
	case int:
		return int64(t), true
	case int64:
		return t, true
	case json.Number:
		n, err := t.Int64()
		return n, err == nil
	}
	return 0, false
}

func validChatID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func deriveChatID(messages []any) string {
	for _, raw := range messages {
		msg, _ := raw.(map[string]any)
		if msg == nil || msg["role"] != "user" {
			continue
		}
		if text, ok := msg["content"].(string); ok && text != "" {
			sum := sha256.Sum256([]byte("codearts:" + text))
			return hex.EncodeToString(sum[:])[:32]
		}
	}
	return RandomHex(16)
}

func chatHeaders(a *Account, chatID string, benefit bool) map[string]string {
	headers := map[string]string{
		"Content-Type":    "application/json",
		"Accept":          "text/event-stream",
		"x-auth-token":    a.CloudDragonToken,
		"x-snap-traceid":  RandomHex(16),
		"X-Language":      "zh-cn",
		"app-id":          "CodeAgent3.0",
		"is_confidential": "false",
	}
	if benefit {
		headers["maas_type"] = "benefit"
	}
	return headers
}

func (m *Manager) openStream(parent context.Context, a *Account, model string, body []byte) (*ChatStream, error) {
	endpoint := SNAPHost + EPChat
	chatID, _ := jsonFieldString(body, "chat_id")
	sessionID := hex.EncodeToString(sha256Bytes("codearts-session:" + chatID))[:32]
	otSession := hex.EncodeToString(sha256Bytes("codearts-ot-session:" + a.UserID))[:32]
	headers := chatHeaders(a, chatID, a.isBenefit(model))
	ak, sk, token := a.Credential()
	signed, err := SignRequest(http.MethodPost, endpoint, headers, body, ak, sk, token, "")
	if err != nil {
		return nil, err
	}
	signed["Chat-Id"] = chatID
	signed["Session-Id"] = sessionID
	signed["x-ot-session-id"] = otSession
	signed["user-session-id"] = otSession
	signed["x-ot-trace-id"] = RandomHex(16)

	ctx, cancel := context.WithCancel(parent)
	timeout := time.Duration(m.Config().StreamTimeoutSeconds * float64(time.Second))
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	timer := time.AfterFunc(timeout, cancel)
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			timer.Stop()
			cancel()
			return nil, err
		}
		for k, v := range signed {
			if strings.EqualFold(k, "Host") {
				continue
			}
			req.Header.Set(k, v)
		}
		resp, err := m.httpClient().Do(req)
		if err != nil {
			timer.Stop()
			cancel()
			return nil, &APIError{Status: 503, Code: "codearts_unreachable", Message: "连不上 CodeArts 聊天接口：" + err.Error()}
		}
		if resp.StatusCode == http.StatusOK {
			return &ChatStream{
				m: m, acct: a, model: model, body: resp.Body,
				reader:  bufio.NewReaderSize(resp.Body, 64*1024),
				created: time.Now().Unix(), cancel: cancel, timer: timer,
			}, nil
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		resp.Body.Close()
		msg := strings.TrimSpace(string(raw))
		switch {
		case resp.StatusCode == 401 || resp.StatusCode == 403:
			timer.Stop()
			cancel()
			return nil, &APIError{Status: resp.StatusCode, Code: "codearts_auth", Message: truncate(msg, 300)}
		case resp.StatusCode == 400 && isConcurrencyMessage(msg):
			lastErr = &APIError{Status: 429, Code: "TM.00001041", Message: truncate(msg, 300)}
			if attempt < 2 {
				select {
				case <-ctx.Done():
					timer.Stop()
					cancel()
					return nil, &APIError{Status: 503, Code: "codearts_timeout", Message: "CodeArts 并发等待超时"}
				case <-time.After(time.Duration(2*(attempt+1)) * time.Second):
				}
				continue
			}
		case resp.StatusCode == 400 && isCreditExhaustedMessage(msg):
			timer.Stop()
			cancel()
			return nil, &APIError{Status: 429, Code: "CREDIT_EXHAUSTED", Message: truncate(msg, 300)}
		case resp.StatusCode == 400:
			timer.Stop()
			cancel()
			return nil, &APIError{Status: 400, Code: "codearts_bad_request", Message: truncate(msg, 300)}
		case resp.StatusCode == 429:
			timer.Stop()
			cancel()
			return nil, &APIError{Status: 429, Code: "429", Message: truncate(msg, 300)}
		default:
			timer.Stop()
			cancel()
			return nil, &APIError{Status: resp.StatusCode, Code: "codearts_http", Message: truncate(msg, 300)}
		}
	}
	timer.Stop()
	cancel()
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, &APIError{Status: 429, Code: "codearts_busy", Message: "CodeArts 并发会话已满"}
}

func jsonFieldString(body []byte, key string) (string, bool) {
	var obj map[string]any
	if json.Unmarshal(body, &obj) != nil {
		return "", false
	}
	s, ok := obj[key].(string)
	return s, ok
}

func sha256Bytes(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

func isConcurrencyMessage(msg string) bool {
	lower := strings.ToLower(msg)
	return strings.Contains(msg, "并发会话") || strings.Contains(lower, "tm.00001041") ||
		strings.Contains(lower, "concurrent session") || strings.Contains(lower, "maximum number of active")
}

func isCreditExhaustedMessage(msg string) bool {
	lower := strings.ToLower(msg)
	return strings.Contains(msg, "积分已耗尽") || strings.Contains(msg, "积分不足") ||
		strings.Contains(lower, "credit exhausted") || strings.Contains(lower, "credits exhausted") ||
		strings.Contains(lower, "insufficient credit") || strings.Contains(lower, "insufficient credits")
}

// ChatStream converts Huawei SSE into OpenAI-compatible SSE chunks.
type ChatStream struct {
	m       *Manager
	acct    *Account
	model   string
	body    io.ReadCloser
	reader  *bufio.Reader
	created int64

	lastText   string
	usage      map[string]any
	finishSent bool
	usageSent  bool
	done       bool
	closeOnce  sync.Once
	cancel     context.CancelFunc
	timer      *time.Timer
}

// Close releases the upstream body and the account slot.
func (s *ChatStream) Close() {
	if s == nil {
		return
	}
	s.closeOnce.Do(func() {
		if s.timer != nil {
			s.timer.Stop()
		}
		if s.body != nil {
			_ = s.body.Close()
		}
		if s.cancel != nil {
			s.cancel()
		}
		if s.acct != nil {
			s.acct.release()
		}
	})
}

// Next returns the next OpenAI chunk, or io.EOF after the terminal [DONE].
func (s *ChatStream) Next() ([]byte, error) {
	if s == nil || s.done {
		return nil, io.EOF
	}
	for {
		line, err := s.reader.ReadString('\n')
		if err != nil {
			if !s.finishSent {
				s.finishSent = true
				return s.finishChunk("stop"), nil
			}
			return s.usageChunk(), nil
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "[DONE]" {
			if !s.finishSent {
				s.finishSent = true
				return s.finishChunk("stop"), nil
			}
			return s.usageChunk(), nil
		}
		var payload map[string]any
		if json.Unmarshal([]byte(data), &payload) != nil {
			continue
		}
		if e, ok := payload["error"].(map[string]any); ok {
			msg, _ := e["message"].(string)
			return nil, &APIError{Status: 502, Code: "codearts_stream_error", Message: truncate(msg, 300)}
		}
		if u, ok := payload["usage"].(map[string]any); ok {
			s.usage = u
		}
		if choices, ok := payload["choices"].([]any); ok && len(choices) > 0 {
			choice, _ := choices[0].(map[string]any)
			delta, _ := choice["delta"].(map[string]any)
			if delta == nil {
				message, _ := choice["message"].(map[string]any)
				if message != nil {
					delta = map[string]any{"role": "assistant"}
					if c, ok := message["content"]; ok {
						delta["content"] = c
					}
					if tc, ok := message["tool_calls"]; ok {
						delta["tool_calls"] = tc
					}
				}
			}
			if delta == nil {
				delta = map[string]any{}
			}
			reason, _ := choice["finish_reason"].(string)
			if reason != "" {
				s.finishSent = true
			}
			return s.chunk(delta, reason), nil
		}
		if delta, ok := payload["delta"].(map[string]any); ok {
			return s.chunk(delta, ""), nil
		}
		if text, ok := payload["text"].(string); ok {
			if strings.TrimSpace(text) == "[DONE]" || strings.EqualFold(strings.TrimSpace(text), "done") {
				s.done = true
				if !s.finishSent {
					return s.finishChunk("stop"), nil
				}
				return s.usageChunk(), nil
			}
			delta := s.textDelta(text)
			if delta == "" {
				continue
			}
			return s.chunk(map[string]any{"content": delta}, ""), nil
		}
		if output, ok := payload["output"].([]any); ok {
			var text strings.Builder
			for _, raw := range output {
				item, _ := raw.(map[string]any)
				if item != nil && item["type"] == "output_text" {
					if t, ok := item["text"].(string); ok {
						text.WriteString(t)
					}
				}
			}
			delta := s.textDelta(text.String())
			if delta != "" {
				return s.chunk(map[string]any{"content": delta}, ""), nil
			}
		}
	}
}

func (s *ChatStream) textDelta(text string) string {
	if text == s.lastText {
		return ""
	}
	delta := text
	if strings.HasPrefix(text, s.lastText) {
		delta = text[len(s.lastText):]
	}
	s.lastText = text
	return delta
}

func (s *ChatStream) chunk(delta map[string]any, finish string) []byte {
	obj := map[string]any{
		"id":      "chatcmpl-codearts",
		"object":  "chat.completion.chunk",
		"created": s.created,
		"model":   s.model,
		"choices": []any{map[string]any{
			"index": 0, "delta": delta, "finish_reason": nilIfEmpty(finish),
		}},
	}
	raw, _ := json.Marshal(obj)
	return append([]byte("data: "), append(raw, '\n', '\n')...)
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (s *ChatStream) finishChunk(reason string) []byte {
	return s.chunk(map[string]any{}, reason)
}

func (s *ChatStream) usageChunk() []byte {
	if s.usageSent || len(s.usage) == 0 {
		s.usageSent = true
		s.done = true
		return []byte("data: [DONE]\n\n")
	}
	obj := map[string]any{
		"id":      "chatcmpl-codearts",
		"object":  "chat.completion.chunk",
		"created": s.created,
		"model":   s.model,
		"choices": []any{},
		"usage":   s.usage,
	}
	raw, _ := json.Marshal(obj)
	s.usageSent = true
	s.done = true
	return append(append([]byte("data: "), raw...), []byte("\n\ndata: [DONE]\n\n")...)
}

// Aggregate consumes the stream and returns a non-streaming chat.completion.
func (s *ChatStream) Aggregate() (map[string]any, error) {
	var content strings.Builder
	var reasoning strings.Builder
	var calls []map[string]any
	usage := map[string]any{}
	finish := "stop"
	callIndex := map[int]map[string]any{}
	for {
		chunk, err := s.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		for _, block := range strings.Split(string(chunk), "\n\n") {
			data := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(block), "data:"))
			if data == "[DONE]" || data == "" {
				continue
			}
			var obj map[string]any
			if json.Unmarshal([]byte(data), &obj) != nil {
				continue
			}
			if u, ok := obj["usage"].(map[string]any); ok {
				usage = u
			}
			choices, _ := obj["choices"].([]any)
			if len(choices) == 0 {
				continue
			}
			choice, _ := choices[0].(map[string]any)
			if r, ok := choice["finish_reason"].(string); ok && r != "" {
				finish = r
			}
			delta, _ := choice["delta"].(map[string]any)
			if delta == nil {
				continue
			}
			if c, ok := delta["content"].(string); ok {
				content.WriteString(c)
			}
			if r, ok := delta["reasoning_content"].(string); ok {
				reasoning.WriteString(r)
			}
			if rawCalls, ok := delta["tool_calls"].([]any); ok {
				for _, raw := range rawCalls {
					call, _ := raw.(map[string]any)
					if call == nil {
						continue
					}
					idx := 0
					if n, ok := numberToInt64(call["index"]); ok {
						idx = int(n)
					}
					merged := callIndex[idx]
					if merged == nil {
						merged = map[string]any{"id": "", "type": "function", "function": map[string]any{"name": "", "arguments": ""}}
						callIndex[idx] = merged
					}
					if id, _ := call["id"].(string); id != "" {
						merged["id"] = id
					}
					if fn, ok := call["function"].(map[string]any); ok {
						mf := merged["function"].(map[string]any)
						if name, _ := fn["name"].(string); name != "" {
							mf["name"] = name
						}
						if args, _ := fn["arguments"].(string); args != "" {
							mf["arguments"] = mf["arguments"].(string) + args
						}
					}
				}
			}
		}
	}
	for _, idx := range sortedIndexes(callIndex) {
		calls = append(calls, callIndex[idx])
	}
	msg := map[string]any{"role": "assistant", "content": content.String()}
	if reasoning.Len() > 0 {
		msg["reasoning_content"] = reasoning.String()
	}
	if len(calls) > 0 {
		msg["tool_calls"] = calls
	}
	out := map[string]any{
		"id":      "chatcmpl-codearts",
		"object":  "chat.completion",
		"created": s.created,
		"model":   s.model,
		"choices": []any{map[string]any{
			"index": 0, "message": msg, "finish_reason": finish,
		}},
	}
	if len(usage) > 0 {
		out["usage"] = usage
	}
	return out, nil
}

func sortedIndexes(m map[int]map[string]any) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}
