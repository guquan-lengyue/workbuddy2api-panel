package codearts

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	oauthTTL     = 600 * time.Second
	refreshSkew  = 30 * time.Minute
	defaultPort  = 7863
	maxTokenBody = 256 << 10
)

// TokenResponse is the normalized /v1/oauth2/tokens payload.
type TokenResponse struct {
	UserID       string      `json:"user_id"`
	UserName     string      `json:"user_name"`
	DomainID     string      `json:"domain_id"`
	RefreshToken string      `json:"refresh_token"`
	Credentials  Credentials `json:"credentials"`
	Credential   Credentials `json:"credential"`
}

// Credentials is the STS temporary credential triple.
type Credentials struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SecurityToken   string `json:"security_token"`
	Expiration      string `json:"expiration"`
	Access          string `json:"access"`
	Secret          string `json:"secret"`
	SecurityTokenLE string `json:"securitytoken"`
	ExpiresAt       string `json:"expires_at"`
}

func (t *TokenResponse) normalize() {
	if t.Credentials.SecurityToken == "" && t.Credentials.SecurityTokenLE != "" {
		t.Credentials = Credentials{
			AccessKeyID:     t.Credentials.Access,
			SecretAccessKey: t.Credentials.Secret,
			SecurityToken:   t.Credentials.SecurityTokenLE,
			Expiration:      t.Credentials.ExpiresAt,
		}
	}
	if t.Credentials.SecurityToken == "" && t.Credential.SecurityToken != "" {
		t.Credentials = t.Credential
	}
	if t.Credentials.SecurityToken == "" && t.Credential.SecurityTokenLE != "" {
		t.Credentials = Credentials{
			AccessKeyID:     t.Credential.Access,
			SecretAccessKey: t.Credential.Secret,
			SecurityToken:   t.Credential.SecurityTokenLE,
			Expiration:      t.Credential.ExpiresAt,
		}
	}
}

// requestToken exchanges an OAuth form for STS credentials.
func requestToken(ctx context.Context, m *Manager, form url.Values, key *ecdsa.PrivateKey) (*TokenResponse, error) {
	if key == nil {
		return nil, errors.New("missing DPoP key")
	}
	endpoint := STSHost + EPOAuthTokens
	proof, err := DPoPProof(key, endpoint)
	if err != nil {
		return nil, err
	}
	body := []byte(form.Encode())
	timeout := time.Duration(m.Config().TimeoutSeconds * float64(time.Second))
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", proof)
	resp, err := m.httpClient().Do(req)
	if err != nil {
		return nil, &APIError{Status: 503, Code: "sts_unreachable", Message: "连不上华为云 STS：" + err.Error()}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxTokenBody))
	if resp.StatusCode >= 400 {
		msg := strings.TrimSpace(string(raw))
		lower := strings.ToLower(msg)
		if strings.Contains(lower, "invalid_grant") || strings.Contains(lower, "expiredrefreshtoken") ||
			strings.Contains(lower, "invaliddpopheader") || strings.Contains(lower, "invalid client id") ||
			strings.Contains(lower, "has been used") {
			return nil, &APIError{Status: 401, Code: "invalid_grant", Message: "refresh_token 或 DPoP 已被拒绝，需要重新登录：" + truncate(msg, 300)}
		}
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			return nil, &APIError{Status: resp.StatusCode, Code: "sts_auth", Message: truncate(msg, 300)}
		}
		return nil, &APIError{Status: resp.StatusCode, Code: "sts_http", Message: truncate(msg, 300)}
	}
	var token TokenResponse
	if err := json.Unmarshal(raw, &token); err != nil {
		return nil, &APIError{Status: 502, Code: "sts_bad_json", Message: "STS 响应不是合法 JSON：" + truncate(string(raw), 200)}
	}
	token.normalize()
	if token.Credentials.SecurityToken == "" {
		return nil, &APIError{Status: 502, Code: "sts_no_token", Message: "登录响应缺少 security_token：" + truncate(string(raw), 300)}
	}
	return &token, nil
}

func exchangeCode(ctx context.Context, m *Manager, code, verifier string, port int, key *ecdsa.PrivateKey) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("client_id", ClientID)
	form.Set("code", code)
	form.Set("code_verifier", verifier)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", fmt.Sprintf("http://127.0.0.1:%d%s", port, RedirectPath))
	return requestToken(ctx, m, form, key)
}

func refreshTokenFor(ctx context.Context, m *Manager, a *Account, key *ecdsa.PrivateKey) (*TokenResponse, error) {
	if strings.TrimSpace(a.RefreshToken) == "" {
		return nil, &APIError{Status: 401, Code: "no_refresh_token", Message: "账号没有 refresh_token，需要重新登录"}
	}
	form := url.Values{}
	clientID := a.ClientID
	if clientID == "" {
		clientID = ClientID
	}
	form.Set("client_id", clientID)
	form.Set("code_verifier", a.CodeVerifier)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", a.RefreshToken)
	return requestToken(ctx, m, form, key)
}

func pollTicket(ctx context.Context, m *Manager, ticketID, secret string) (*TokenResponse, error) {
	endpoint := SNAPManager + EPLoginTicket + "?" + url.Values{
		"ticket_id": {ticketID},
		"secret":    {secret},
	}.Encode()
	timeout := time.Duration(m.Config().TimeoutSeconds * float64(time.Second))
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("plugin-name", PluginName)
	req.Header.Set("plugin-version", PluginVersion)
	resp, err := m.httpClient().Do(req)
	if err != nil {
		return nil, &APIError{Status: 503, Code: "ticket_unreachable", Message: err.Error()}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxTokenBody))
	if resp.StatusCode >= 400 {
		return nil, &APIError{Status: resp.StatusCode, Code: "ticket_http", Message: truncate(string(raw), 300)}
	}
	var token TokenResponse
	if err := json.Unmarshal(raw, &token); err != nil {
		return nil, &APIError{Status: 502, Code: "ticket_bad_json", Message: truncate(string(raw), 200)}
	}
	token.normalize()
	return &token, nil
}

// OAuthSession is an in-flight browser authorization.
type OAuthSession struct {
	ID             string
	TicketID       string
	Secret         string
	Verifier       string
	DPoPKey        *ecdsa.PrivateKey
	Port           int
	CreatedAt      time.Time
	Status         string
	Message        string
	AuthURL        string
	TicketFallback bool
	AccountUID     string
	AccountName    string
}

type OAuthStartResult struct {
	OK        bool   `json:"ok"`
	SessionID string `json:"session_id"`
	AuthURL   string `json:"auth_url"`
	ExpiresIn int    `json:"expires_in"`
	Message   string `json:"message"`
}

type OAuthStatus struct {
	OK        bool   `json:"ok"`
	Status    string `json:"status"`
	Message   string `json:"message"`
	SessionID string `json:"session_id"`
	AuthURL   string `json:"auth_url,omitempty"`
	UID       string `json:"uid,omitempty"`
	Nickname  string `json:"nickname,omitempty"`
}

func (s *OAuthSession) public() *OAuthStatus {
	out := &OAuthStatus{
		OK: s.Status != "error", Status: s.Status, Message: s.Message,
		SessionID: s.ID, AuthURL: s.AuthURL, UID: s.AccountUID, Nickname: s.AccountName,
	}
	return out
}

func (m *Manager) gcOAuth(now time.Time) {
	m.oauthMu.Lock()
	defer m.oauthMu.Unlock()
	for id, s := range m.oauth {
		if now.Sub(s.CreatedAt) > oauthTTL {
			delete(m.oauth, id)
		}
	}
}

// OAuthStart returns a Huawei Cloud authorization URL and stores the session.
func (m *Manager) OAuthStart(port int) (*OAuthStartResult, error) {
	if m == nil {
		return nil, errors.New("codearts manager is nil")
	}
	if port <= 0 {
		port = m.callbackPortValue()
	}
	if port <= 0 {
		port = defaultPort
	}
	key, err := GenerateKey()
	if err != nil {
		return nil, err
	}
	verifier, challenge, err := PKCEPair()
	if err != nil {
		return nil, err
	}
	ticketID := RandomHex(16)
	secret := RandomHex(16)
	sessionID := RandomHex(8)
	q := url.Values{}
	q.Set("theme", "2")
	q.Set("locale", "zh-cn")
	q.Set("uri_scheme", ClientID)
	q.Set("client_id", ClientID)
	q.Set("port", strconv.Itoa(port))
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "SHA-256")
	q.Set("ticket_id", ticketID)
	q.Set("plugin-name", PluginName)
	q.Set("plugin-version", PluginVersion)
	authURL := PortalHost + "/authorize?" + q.Encode()
	s := &OAuthSession{
		ID: sessionID, TicketID: ticketID, Secret: secret, Verifier: verifier,
		DPoPKey: key, Port: port, CreatedAt: time.Now(), Status: "pending",
		Message: "等待浏览器完成授权…", AuthURL: authURL,
	}
	m.oauthMu.Lock()
	m.oauth[sessionID] = s
	m.oauthMu.Unlock()
	return &OAuthStartResult{
		OK: true, SessionID: sessionID, AuthURL: authURL,
		ExpiresIn: int(oauthTTL / time.Second),
		Message:   "请在浏览器打开授权链接，完成后等待自动检测",
	}, nil
}

func (m *Manager) findSession(id string) *OAuthSession {
	m.gcOAuth(time.Now())
	m.oauthMu.Lock()
	defer m.oauthMu.Unlock()
	if id != "" {
		return m.oauth[id]
	}
	var latest *OAuthSession
	for _, s := range m.oauth {
		if s.Status != "pending" {
			continue
		}
		if latest == nil || s.CreatedAt.After(latest.CreatedAt) {
			latest = s
		}
	}
	return latest
}

// OAuthPoll checks an authorization session.
func (m *Manager) OAuthPoll(id string) (*OAuthStatus, error) {
	s := m.findSession(id)
	if s == nil {
		return nil, &APIError{Status: 404, Code: "oauth_not_found", Message: "授权会话不存在或已过期，请重新发起授权"}
	}
	if s.Status == "pending" && s.TicketFallback {
		token, err := pollTicket(context.Background(), m, s.TicketID, s.Secret)
		if err == nil && token.Credentials.SecurityToken != "" && token.UserID != "" {
			if _, saveErr := m.saveLogin(s, token); saveErr != nil {
				s.Status = "error"
				s.Message = saveErr.Error()
			}
		} else if err != nil {
			s.Message = "等待浏览器完成登录…"
		}
	}
	return s.public(), nil
}

// OAuthCallbackURL processes a Huawei callback URL. The browser route passes
// the whole URL; session is resolved by session_id, ticket_id or the latest
// pending session.
func (m *Manager) OAuthCallbackURL(callbackURL string) (*OAuthStatus, error) {
	u, err := url.Parse(strings.TrimSpace(callbackURL))
	if err != nil {
		return nil, &APIError{Status: 400, Code: "oauth_bad_url", Message: "无法解析回调地址"}
	}
	if u.Scheme != "http" || u.User != nil || u.Path != RedirectPath {
		return nil, &APIError{Status: 400, Code: "oauth_bad_url", Message: "只接受华为返回的 127.0.0.1 OAuth 回调地址"}
	}
	host := strings.ToLower(u.Hostname())
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return nil, &APIError{Status: 400, Code: "oauth_bad_url", Message: "只接受本机回环 OAuth 回调"}
	}
	q := u.Query()
	id := q.Get("session_id")
	s := m.findSession(id)
	if s == nil && q.Get("ticket_id") != "" {
		m.oauthMu.Lock()
		for _, cur := range m.oauth {
			if cur.TicketID == q.Get("ticket_id") && cur.Status == "pending" {
				s = cur
				break
			}
		}
		m.oauthMu.Unlock()
	}
	if s == nil {
		return nil, &APIError{Status: 404, Code: "oauth_not_found", Message: "授权会话不存在或已过期，请重新发起授权"}
	}
	if u.Port() != "" && s.Port != 0 {
		p, _ := strconv.Atoi(u.Port())
		if p != s.Port {
			return nil, &APIError{Status: 400, Code: "oauth_bad_port", Message: "回调端口与当前授权会话不匹配"}
		}
	}
	if code := q.Get("code"); code != "" {
		token, err := exchangeCode(context.Background(), m, code, s.Verifier, s.Port, s.DPoPKey)
		if err != nil {
			s.Status = "error"
			s.Message = err.Error()
			return s.public(), err
		}
		if _, err := m.saveLogin(s, token); err != nil {
			s.Status = "error"
			s.Message = err.Error()
			return s.public(), err
		}
		return s.public(), nil
	}
	if q.Get("secret") != "" && q.Get("redirect") != "" {
		s.TicketFallback = true
		token, err := pollTicket(context.Background(), m, s.TicketID, q.Get("secret"))
		if err != nil {
			s.Message = "等待浏览器完成登录…"
			return s.public(), nil
		}
		if token.Credentials.SecurityToken != "" && token.UserID != "" {
			if _, err := m.saveLogin(s, token); err != nil {
				s.Status = "error"
				s.Message = err.Error()
				return s.public(), err
			}
		}
		return s.public(), nil
	}
	return nil, &APIError{Status: 400, Code: "oauth_no_code", Message: "回调里没有 code；请把浏览器地址栏的完整回调 URL 粘贴到面板"}
}

func safeUID(uid string) string {
	r := strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_")
	return r.Replace(strings.TrimSpace(uid))
}

func uidFromRefreshToken(refresh string) string {
	parts := strings.Split(refresh, ".")
	if len(parts) < 2 {
		return ""
	}
	raw, err := b64urlDecode(parts[1])
	if err != nil {
		return ""
	}
	var payload struct {
		Sub string `json:"sub"`
	}
	if json.Unmarshal(raw, &payload) != nil {
		return ""
	}
	return strings.TrimSpace(payload.Sub)
}

func (m *Manager) saveLogin(s *OAuthSession, token *TokenResponse) (*Account, error) {
	token.normalize()
	uid := strings.TrimSpace(token.UserID)
	if uid == "" {
		uid = uidFromRefreshToken(token.RefreshToken)
	}
	if uid == "" {
		sum := sha256.Sum256([]byte(token.RefreshToken))
		uid = "codearts-" + hex.EncodeToString(sum[:])[:12]
	}
	name := strings.TrimSpace(token.UserName)
	if name == "" {
		name = uid
	}
	if m.dir == "" {
		return nil, errors.New("CodeArts 数据目录为空")
	}
	path := filepath.Join(m.dir, "codearts-"+safeUID(uid)+".json")
	a := &Account{
		UserID: uid, UserName: name, DomainID: token.DomainID,
		CloudDragonToken: token.Credentials.SecurityToken,
		AccessKeyID:      token.Credentials.AccessKeyID,
		SecretAccessKey:  token.Credentials.SecretAccessKey,
		Expiration:       token.Credentials.Expiration,
		RefreshToken:     token.RefreshToken,
		CodeVerifier:     s.Verifier,
		ClientID:         ClientID,
		DPoPPrivateKey:   PrivateJWK(s.DPoPKey),
		UpdatedAt:        time.Now().Unix(),
		FilePath:         path,
		tasks:            true,
	}
	if err := m.saveAccount(a); err != nil {
		return nil, err
	}
	m.addAccount(a)
	m.saveState()
	s.Status = "done"
	s.Message = "登录成功：" + name
	s.AccountUID = uid
	s.AccountName = name
	return a, nil
}

func (a *Account) applyToken(token *TokenResponse) {
	token.normalize()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.UserID = firstNonEmpty(token.UserID, a.UserID)
	a.UserName = firstNonEmpty(token.UserName, a.UserName)
	a.DomainID = firstNonEmpty(token.DomainID, a.DomainID)
	a.CloudDragonToken = token.Credentials.SecurityToken
	a.AccessKeyID = token.Credentials.AccessKeyID
	a.SecretAccessKey = token.Credentials.SecretAccessKey
	a.Expiration = token.Credentials.Expiration
	a.RefreshToken = firstNonEmpty(token.RefreshToken, a.RefreshToken)
	a.UpdatedAt = time.Now().Unix()
	if !a.manual {
		a.disabled = false
		a.disabledWhy = ""
		a.lastError = ""
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// ensureToken refreshes an expiring STS credential once per account.
func ensureToken(ctx context.Context, m *Manager, a *Account) error {
	if a == nil {
		return ErrNoAccount
	}
	if !a.ExpiringSoon(refreshSkew) {
		return nil
	}
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()
	if !a.ExpiringSoon(refreshSkew) {
		return nil
	}
	key, err := a.DPOPKey()
	if err != nil {
		key, err = GenerateKey()
		if err != nil {
			return err
		}
		a.mu.Lock()
		a.DPoPPrivateKey = PrivateJWK(key)
		a.mu.Unlock()
	}
	token, err := refreshTokenFor(ctx, m, a, key)
	if err != nil {
		if errors.Is(err, ErrAuth) {
			a.noteError(err.Error(), false, true, 0)
			m.saveState()
		}
		return err
	}
	a.applyToken(token)
	if err := m.saveAccount(a); err != nil {
		return err
	}
	m.saveState()
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
