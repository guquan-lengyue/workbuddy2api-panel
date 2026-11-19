package codearts

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	SNAPHost      = "https://snap-access.cn-north-4.myhuaweicloud.com"
	SNAPManager   = SNAPHost + "/snap-manager"
	PortalHost    = "https://codearts.huaweicloud.com/portal"
	STSHost       = "https://sts.cn-north-4.myhuaweicloud.com"
	BenefitHost   = "https://opengw.developer.huaweicloud.com"
	ClientID      = "codearts-agent"
	PluginName    = "snap_AIIDE"
	PluginVersion = "5.2.0"
	RedirectPath  = "/oauth/callback"

	EPChat          = "/api/v2/chat/completions"
	EPOAuthTokens   = "/v1/oauth2/tokens"
	EPLoginTicket   = "/v1/login/ticket"
	EPModelBuiltin  = "/v1/model/builtin"
	EPAgentList     = "/v1/agent-center/agents/useragents"
	EPAgentDetail   = "/v1/agent-center/agents/detail"
	EPBenefitConfig = "/api/v1/gateway/config"
	EPBenefitClaim  = "/api/v1/benefit/claim"
	EPPackageInfo   = "/v1/statistics/plugin"
)

// Account is the persisted CodeArts credential file. JSON tags stay compatible
// with the Python implementation (accounts/codearts/codearts-<uid>.json).
type Account struct {
	UserID           string            `json:"user_id"`
	UserName         string            `json:"user_name"`
	DomainID         string            `json:"domain_id"`
	CloudDragonToken string            `json:"cloud_dragon_token"`
	AccessKeyID      string            `json:"access_key_id"`
	SecretAccessKey  string            `json:"secret_access_key"`
	Expiration       string            `json:"expiration"`
	RefreshToken     string            `json:"refresh_token"`
	CodeVerifier     string            `json:"code_verifier"`
	ClientID         string            `json:"client_id"`
	DPoPPrivateKey   map[string]string `json:"dpop_private_key"`
	UpdatedAt        int64             `json:"updated_at"`

	FilePath string `json:"-"`

	mu          sync.Mutex
	refreshMu   sync.Mutex
	active      int
	disabled    bool
	manual      bool
	disabledWhy string
	coolUntil   time.Time
	errCount    int
	lastError   string
	note        string
	tasks       bool
	checkin     map[string]any
	models      []Model
	benefit     map[string]bool
	modelsAt    time.Time
}

// Model is one CodeArts catalogue entry.
type Model struct {
	ID             string `json:"id"`
	Name           string `json:"name,omitempty"`
	ContextWindow  int64  `json:"context_window,omitempty"`
	MaxTokens      int64  `json:"max_tokens,omitempty"`
	Description    string `json:"description,omitempty"`
	Benefit        bool   `json:"benefit,omitempty"`
	SupportsImages *bool  `json:"supports_images,omitempty"`
	Credits        string `json:"credits,omitempty"`
}

// AccountView is the panel-facing account snapshot.
type AccountView struct {
	UID            string `json:"uid"`
	Name           string `json:"name"`
	Realm          string `json:"realm"`
	Disabled       bool   `json:"disabled"`
	ManualDisabled bool   `json:"manual_disabled"`
	Cooling        bool   `json:"cooling"`
	Until          string `json:"until,omitempty"`
	ErrCount       int    `json:"err_count"`
	Reason         string `json:"reason,omitempty"`
	LastError      string `json:"last_error,omitempty"`
	Active         int    `json:"active"`
	MaxConcurrent  int    `json:"max_concurrent"`
	TokenRemaining string `json:"token_remaining,omitempty"`
	ExpiresAt      string `json:"expires_at,omitempty"`
	Models         int    `json:"models"`
	Note           string `json:"note,omitempty"`
	TasksEnabled   bool   `json:"tasks_enabled"`
	Checkin        any    `json:"checkin,omitempty"`
}

type AccountState struct {
	Name           string         `json:"name"`
	ErrCount       int            `json:"err_count"`
	CoolUntil      float64        `json:"cool_until"`
	Disabled       bool           `json:"disabled"`
	ManualDisabled bool           `json:"manual_disabled"`
	Reason         string         `json:"reason"`
	LastError      string         `json:"last_error"`
	Checkin        map[string]any `json:"checkin,omitempty"`
	Note           string         `json:"note"`
	TasksEnabled   bool           `json:"tasks_enabled"`
}

// DPOPKey restores the persisted DPoP key.
func (a *Account) DPOPKey() (*ecdsa.PrivateKey, error) {
	if a == nil || len(a.DPoPPrivateKey) == 0 {
		return nil, errors.New("missing DPoP private key")
	}
	return KeyFromJWK(a.DPoPPrivateKey)
}

// Credential is the current STS credential triple.
func (a *Account) Credential() (ak, sk, token string) {
	if a == nil {
		return "", "", ""
	}
	return a.AccessKeyID, a.SecretAccessKey, a.CloudDragonToken
}

// ExpiresAt parses the STS expiration (RFC3339-ish) into local time.
func (a *Account) ExpiresAt() time.Time {
	if a == nil {
		return time.Time{}
	}
	text := strings.TrimSpace(a.Expiration)
	if text == "" {
		return time.Time{}
	}
	text = strings.Replace(text, "Z", "+00:00", 1)
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, text); err == nil {
			return t
		}
	}
	return time.Time{}
}

// ExpiringSoon reports whether the STS credential needs a refresh.
func (a *Account) ExpiringSoon(skew time.Duration) bool {
	exp := a.ExpiresAt()
	if exp.IsZero() {
		return false
	}
	return time.Until(exp) <= skew
}

func parseExpirationMillis(v any) int64 {
	switch t := v.(type) {
	case float64:
		if t > 1e11 {
			return int64(t / 1000)
		}
		return int64(t)
	case string:
		n, _ := strconv.ParseInt(t, 10, 64)
		if n > 1e11 {
			return n / 1000
		}
		return n
	}
	return 0
}

func (a *Account) view(maxConcurrent int) AccountView {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	cooling := !a.disabled && now.Before(a.coolUntil)
	reason := a.disabledWhy
	if reason == "" {
		reason = a.lastError
	}
	v := AccountView{
		UID: a.UserID, Name: a.UserName, Realm: "codearts",
		Disabled: a.disabled, ManualDisabled: a.manual, Cooling: cooling,
		ErrCount: a.errCount, Reason: reason, LastError: a.lastError,
		Active: a.active, MaxConcurrent: maxConcurrent,
		Models: len(a.models), Note: a.note, TasksEnabled: a.tasks,
		Checkin: a.checkin,
	}
	if cooling {
		v.Until = a.coolUntil.Format(time.RFC3339)
	}
	if exp := a.ExpiresAt(); !exp.IsZero() {
		v.ExpiresAt = exp.Format(time.RFC3339)
		remaining := time.Until(exp)
		if remaining < 0 {
			remaining = 0
		}
		h := int(remaining.Hours())
		m := int(remaining.Minutes()) % 60
		if h > 0 {
			v.TokenRemaining = fmt.Sprintf("%dh%dm", h, m)
		} else {
			v.TokenRemaining = fmt.Sprintf("%dm", m)
		}
	}
	return v
}

func (a *Account) available(now time.Time, maxConcurrent int) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.disabled || now.Before(a.coolUntil) {
		return false
	}
	return a.active < maxConcurrent
}

func (a *Account) acquire(maxConcurrent int) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.disabled || time.Now().Before(a.coolUntil) || a.active >= maxConcurrent {
		return false
	}
	a.active++
	return true
}

func (a *Account) release() {
	a.mu.Lock()
	if a.active > 0 {
		a.active--
	}
	a.mu.Unlock()
}

func (a *Account) noteSuccess() {
	a.mu.Lock()
	a.errCount = 0
	a.coolUntil = time.Time{}
	a.lastError = ""
	a.mu.Unlock()
}

func (a *Account) noteError(msg string, soft bool, terminal bool, cooldown time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastError = msg
	a.errCount++
	if terminal || a.errCount >= 3 {
		a.disabled = true
		a.disabledWhy = msg
		a.errCount = 0
		return
	}
	if cooldown <= 0 {
		if soft {
			cooldown = 60 * time.Second
		} else {
			cooldown = 10 * time.Minute
		}
	}
	a.coolUntil = time.Now().Add(cooldown)
}

func (a *Account) setModels(models []Model) {
	a.mu.Lock()
	a.models = models
	a.benefit = make(map[string]bool, len(models))
	for _, m := range models {
		a.benefit[strings.ToLower(m.ID)] = m.Benefit
	}
	a.modelsAt = time.Now()
	a.mu.Unlock()
}

func (a *Account) modelList() []Model {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]Model(nil), a.models...)
}

func (a *Account) hasModel(model string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.models) == 0 {
		return true
	}
	for _, m := range a.models {
		if strings.EqualFold(m.ID, model) {
			return true
		}
	}
	return false
}

func (a *Account) canonicalModel(model string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, m := range a.models {
		if strings.EqualFold(m.ID, model) {
			return m.ID
		}
	}
	return model
}

func (a *Account) isBenefit(model string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.benefit[strings.ToLower(model)]
}

func (a *Account) outputLimit(model string) int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, m := range a.models {
		if strings.EqualFold(m.ID, model) {
			if m.MaxTokens > 0 {
				return m.MaxTokens
			}
		}
	}
	return 65536
}

func (a *Account) manualDisable(reason string) {
	a.mu.Lock()
	a.manual = true
	a.disabled = true
	a.disabledWhy = reason
	a.mu.Unlock()
}

func (a *Account) manualEnable() {
	a.mu.Lock()
	a.manual = false
	a.disabled = false
	a.disabledWhy = ""
	a.lastError = ""
	a.errCount = 0
	a.coolUntil = time.Time{}
	a.mu.Unlock()
}

func (a *Account) state() AccountState {
	a.mu.Lock()
	defer a.mu.Unlock()
	return AccountState{
		Name: a.UserID, ErrCount: a.errCount,
		CoolUntil: float64(a.coolUntil.Unix()), Disabled: a.disabled,
		ManualDisabled: a.manual, Reason: a.disabledWhy, LastError: a.lastError,
		Checkin: a.checkin, Note: a.note, TasksEnabled: a.tasks,
	}
}

func (a *Account) applyState(st AccountState) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.errCount = st.ErrCount
	a.coolUntil = time.Unix(int64(st.CoolUntil), 0)
	a.disabled = st.Disabled
	a.manual = st.ManualDisabled
	a.disabledWhy = st.Reason
	a.lastError = st.LastError
	a.checkin = st.Checkin
	a.note = st.Note
	a.tasks = st.TasksEnabled
}

// parseJSONNumber is a small helper for catalogue responses that may encode
// numbers as strings.
func parseJSONNumber(v any) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case json.Number:
		n, _ := t.Int64()
		return n
	case string:
		n, _ := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
		return n
	}
	return 0
}

// keyOnCurve is used by tests and by the JWK loader.
func keyOnCurve(x, y *big.Int) bool {
	return elliptic.P256().IsOnCurve(x, y)
}
