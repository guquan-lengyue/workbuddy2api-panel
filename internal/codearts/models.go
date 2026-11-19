package codearts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	catalogTTL    = time.Hour
	catalogMinGap = time.Minute
	defaultMaxOut = int64(65536)
)

var seedIDs = []string{
	"GLM-5.2", "GLM-5.2-ArkTS-SPARK", "GLM-5.1", "GLM-4.7",
	"OpenPangu-2.0-Pro", "OpenPangu-2.0-Flash",
	"Qwen3-VL-235B", "Qwen3.5-397B-A17B-VL", "Qwen3.6-27B-VL",
	"deepseek-v4-flash-0731", "deepseek-v4-pro-0813", "glm-5.3-flash",
}

// SeedModels is the cold-start list used before discovery succeeds. The
// benefit list is a subset; a seed entry is not proof that an account can call
// that model.
func SeedModels() []Model {
	out := make([]Model, 0, len(seedIDs))
	for _, id := range seedIDs {
		benefit := id == "deepseek-v4-flash-0731" ||
			id == "deepseek-v4-pro-0813" ||
			strings.EqualFold(id, "glm-5.3-flash")
		out = append(out, Model{ID: id, Name: id, Benefit: benefit})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (m *Manager) applyAuthorization(a *Account, req *http.Request, body []byte) error {
	if a == nil {
		return ErrNoAccount
	}
	ak, sk, token := a.Credential()
	headers := map[string]string{}
	for k, vs := range req.Header {
		if len(vs) > 0 {
			headers[k] = vs[0]
		}
	}
	signed, err := SignRequest(req.Method, req.URL.String(), headers, body, ak, sk, token, "")
	if err != nil {
		return err
	}
	for k, v := range signed {
		if strings.EqualFold(k, "Host") {
			continue
		}
		req.Header.Set(k, v)
	}
	return nil
}

func (m *Manager) signedJSON(ctx context.Context, a *Account, method, endpoint string, payload any, agentType string) (map[string]any, error) {
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			return nil, err
		}
	}
	timeout := time.Duration(m.Config().TimeoutSeconds * float64(time.Second))
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Language", "zh-cn")
	if agentType != "" {
		req.Header.Set("Agent-Type", agentType)
	}
	if err := m.applyAuthorization(a, req, body); err != nil {
		return nil, err
	}
	resp, err := m.httpClient().Do(req)
	if err != nil {
		return nil, &APIError{Status: 503, Code: "codearts_unreachable", Message: "连不上 CodeArts：" + err.Error()}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, &APIError{Status: resp.StatusCode, Code: "codearts_auth", Message: truncate(string(raw), 300)}
	}
	if resp.StatusCode >= 400 {
		return nil, &APIError{Status: resp.StatusCode, Code: "codearts_http", Message: truncate(string(raw), 300)}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, &APIError{Status: 502, Code: "codearts_bad_json", Message: truncate(string(raw), 200)}
	}
	return out, nil
}

func (m *Manager) fetchAgentModels(ctx context.Context, a *Account) ([]Model, error) {
	u := SNAPHost + EPAgentList + "?" + url.Values{
		"offset": {"0"}, "limit": {"100"}, "is_primary_agent": {"true"},
	}.Encode()
	listing, err := m.signedJSON(ctx, a, http.MethodGet, u, nil, "PromptCenter")
	if err != nil {
		return nil, err
	}
	agents, _ := listing["agents"].([]any)
	agentID := ""
	fallbackID := ""
	for _, raw := range agents {
		item, _ := raw.(map[string]any)
		if item == nil {
			continue
		}
		if fallbackID == "" && item["is_primary_agent"] == true {
			fallbackID, _ = item["agent_id"].(string)
		}
		alias, _ := item["alias"].(map[string]any)
		name, _ := item["agent_name"].(string)
		zh, _ := alias["alias_zh_cn"].(string)
		show, _ := item["show_in_ide"].(bool)
		if name == "CodeAgent" && zh == "智能体" && show {
			agentID, _ = item["agent_id"].(string)
			break
		}
	}
	if agentID == "" {
		agentID = fallbackID
	}
	if agentID == "" && len(agents) > 0 {
		if item, _ := agents[0].(map[string]any); item != nil {
			agentID, _ = item["agent_id"].(string)
		}
	}
	if agentID == "" {
		return nil, nil
	}
	detailURL := SNAPHost + EPAgentDetail + "?" + url.Values{"agent_id": {agentID}}.Encode()
	detail, err := m.signedJSON(ctx, a, http.MethodGet, detailURL, nil, "PromptCenter")
	if err != nil {
		return nil, err
	}
	gpts, _ := detail["gpts"].(map[string]any)
	rawModels, _ := gpts["models"].([]any)
	var out []Model
	for _, raw := range rawModels {
		item, _ := raw.(map[string]any)
		if item == nil {
			continue
		}
		params, _ := item["model_parameters"].(map[string]any)
		mid := firstString(item["model_name"], item["model_id"], item["model_alias"])
		if mid == "" && params != nil {
			mid = firstString(params["model_id"])
		}
		if mid == "" {
			continue
		}
		out = append(out, Model{
			ID: mid, Name: mid,
			ContextWindow:  parseJSONNumber(params["context_window"]),
			MaxTokens:      parseJSONNumber(params["max_tokens"]),
			Description:    firstString(params["model_desc"]),
			SupportsImages: boolPtr(params["supports_images"], item["supports_images"]),
		})
	}
	return out, nil
}

func (m *Manager) fetchBuiltinModels(ctx context.Context, a *Account) ([]Model, error) {
	data, err := m.signedJSON(ctx, a, http.MethodGet, SNAPHost+EPModelBuiltin, nil, "PromptCenter")
	if err != nil {
		return nil, err
	}
	rawModels, _ := data["builtinModels"].([]any)
	var out []Model
	for _, raw := range rawModels {
		item, _ := raw.(map[string]any)
		if item == nil {
			continue
		}
		mid := firstString(item["model_id"], item["model_name"])
		if mid == "" {
			continue
		}
		out = append(out, Model{
			ID: mid, Name: mid,
			ContextWindow:  parseJSONNumber(item["context_window"]),
			MaxTokens:      parseJSONNumber(item["max_tokens"]),
			Description:    firstString(item["model_desc"]),
			SupportsImages: boolPtr(item["supports_images"]),
			Credits:        creditLabel(item["credit"]),
		})
	}
	return out, nil
}

func (m *Manager) fetchBenefitModels(ctx context.Context, a *Account, autoClaim bool) ([]Model, error) {
	if autoClaim {
		_, _ = m.signedJSON(ctx, a, http.MethodPost, BenefitHost+EPBenefitClaim, map[string]any{}, "")
	}
	data, err := m.signedJSON(ctx, a, http.MethodGet, BenefitHost+EPBenefitConfig, nil, "")
	if err != nil {
		return nil, err
	}
	result, _ := data["result"].(map[string]any)
	rawModels, _ := result["models"].([]any)
	var out []Model
	for _, raw := range rawModels {
		item, _ := raw.(map[string]any)
		if item == nil {
			continue
		}
		mid := firstString(item["model_id"], item["model_name"])
		if mid == "" {
			continue
		}
		out = append(out, Model{
			ID: mid, Name: firstString(item["model_name"], mid),
			ContextWindow:  parseJSONNumber(item["context_window"]),
			MaxTokens:      parseJSONNumber(item["max_tokens"]),
			Description:    firstString(item["model_desc"]),
			Benefit:        true,
			SupportsImages: boolPtr(item["supports_images"]),
		})
	}
	return out, nil
}

func mergeModels(sets ...[]Model) []Model {
	byID := map[string]Model{}
	for _, set := range sets {
		for _, mi := range set {
			key := strings.ToLower(strings.TrimSpace(mi.ID))
			if key == "" {
				continue
			}
			cur, ok := byID[key]
			if !ok {
				byID[key] = mi
				continue
			}
			if cur.ContextWindow == 0 && mi.ContextWindow != 0 {
				cur.ContextWindow = mi.ContextWindow
			}
			if cur.MaxTokens == 0 && mi.MaxTokens != 0 {
				cur.MaxTokens = mi.MaxTokens
			}
			if cur.Description == "" {
				cur.Description = mi.Description
			}
			cur.Benefit = cur.Benefit || mi.Benefit
			if cur.SupportsImages == nil {
				cur.SupportsImages = mi.SupportsImages
			}
			if cur.Credits == "" {
				cur.Credits = mi.Credits
			}
			byID[key] = cur
		}
	}
	out := make([]Model, 0, len(byID))
	for _, mi := range byID {
		out = append(out, mi)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (m *Manager) ensureModels(ctx context.Context, a *Account, force bool) []Model {
	if a == nil {
		return nil
	}
	ttl := time.Duration(m.Config().ModelsTTLSeconds * float64(time.Second))
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if ttl > catalogTTL {
		ttl = catalogTTL
	}
	a.mu.Lock()
	age := time.Since(a.modelsAt)
	existing := append([]Model(nil), a.models...)
	a.mu.Unlock()
	if len(existing) > 0 && !force && age < ttl && age < catalogMinGap {
		return existing
	}
	if len(existing) > 0 && !force && age < ttl {
		return existing
	}
	if err := ensureToken(ctx, m, a); err != nil {
		if len(existing) > 0 {
			return existing
		}
		return SeedModels()
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var sets [][]Model
	var errs []string
	add := func(models []Model, err error) {
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			errs = append(errs, err.Error())
		}
		if len(models) > 0 {
			sets = append(sets, models)
		}
	}
	wg.Add(3)
	go func() { defer wg.Done(); models, err := m.fetchAgentModels(ctx, a); add(models, err) }()
	go func() { defer wg.Done(); models, err := m.fetchBuiltinModels(ctx, a); add(models, err) }()
	go func() {
		defer wg.Done()
		models, err := m.fetchBenefitModels(ctx, a, m.Config().BenefitAutoClaim)
		add(models, err)
	}()
	wg.Wait()
	merged := mergeModels(sets...)
	if len(merged) == 0 {
		if len(existing) > 0 {
			return existing
		}
		merged = SeedModels()
	}
	a.setModels(merged)
	return merged
}

func firstString(values ...any) string {
	for _, v := range values {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func boolPtr(values ...any) *bool {
	for _, v := range values {
		if b, ok := v.(bool); ok {
			out := b
			return &out
		}
	}
	return nil
}

func creditLabel(v any) string {
	rows, _ := v.([]any)
	for _, raw := range rows {
		row, _ := raw.(map[string]any)
		if row == nil {
			continue
		}
		if slot, _ := row["time_slot_id"].(string); slot != "" && slot != "default" {
			continue
		}
		text := strings.ToLower(strings.TrimSpace(firstString(row["ratio_display"])))
		if strings.HasSuffix(text, "x") {
			return "x" + strings.TrimSuffix(text, "x")
		}
	}
	return ""
}

// defaultOutputLimit is the conservative cap when the catalogue has no value.
func defaultOutputLimit() int64 { return defaultMaxOut }

// ensureModelsError is a helper for callers that want the last discovery error.
func ensureModelsError(errs []string) error {
	if len(errs) == 0 {
		return nil
	}
	return errors.New(strings.Join(errs, "; "))
}
