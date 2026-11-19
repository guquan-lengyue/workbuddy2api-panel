package codearts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/misakano7545/workbuddy2api-panel/internal/safefile"
)

// Manager owns the CodeArts configuration, account pool and model cache.
type Manager struct {
	dir string

	mu       sync.RWMutex
	cfg      Config
	accounts []*Account
	next     int
	http     *http.Client

	oauthMu sync.Mutex
	oauth   map[string]*OAuthSession

	callbackPort int
}

// NewManager loads <dir>/config.json, account files and state.json. A missing
// directory is valid: CodeArts stays disabled until configured.
func NewManager(dir string) *Manager {
	m := &Manager{
		dir:   dir,
		cfg:   DefaultConfig(),
		oauth: map[string]*OAuthSession{},
		http: &http.Client{
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 15 * time.Second}).DialContext,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 0,
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   20,
				IdleConnTimeout:       30 * time.Second,
			},
		},
	}
	if dir == "" {
		return m
	}
	if cfg, err := LoadConfig(dir); err == nil {
		m.cfg = cfg
	} else {
		log.Printf("WARN: [codearts] 读取配置失败，使用默认值: %v", err)
	}
	m.loadAccounts()
	return m
}

// SetCallbackPort records the gateway's listen port for OAuth redirect_uri.
func (m *Manager) SetCallbackPort(port int) {
	m.mu.Lock()
	m.callbackPort = port
	m.mu.Unlock()
}

func (m *Manager) callbackPortValue() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.callbackPort
}

// Close releases idle upstream connections.
func (m *Manager) Close() {
	if m != nil && m.http != nil {
		m.http.CloseIdleConnections()
	}
}

// Enabled reports whether the CodeArts egress is on.
func (m *Manager) Enabled() bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.Enabled
}

// Config returns a copy of the current settings.
func (m *Manager) Config() Config {
	if m == nil {
		return DefaultConfig()
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

// Configure persists and applies a new config.
func (m *Manager) Configure(cfg Config) error {
	if m == nil {
		return errors.New("codearts manager is nil")
	}
	if err := SaveConfig(m.dir, cfg); err != nil {
		return err
	}
	m.mu.Lock()
	m.cfg = cfg
	m.mu.Unlock()
	return nil
}

func (m *Manager) accountFiles() ([]string, error) {
	if m.dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "codearts-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		out = append(out, filepath.Join(m.dir, name))
	}
	sort.Strings(out)
	return out, nil
}

func (m *Manager) loadAccounts() {
	files, err := m.accountFiles()
	if err != nil {
		log.Printf("WARN: [codearts] 读取账号目录失败: %v", err)
		return
	}
	states := m.loadState()
	var accounts []*Account
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var a Account
		if err := json.Unmarshal(raw, &a); err != nil {
			log.Printf("WARN: [codearts] 解析 %s 失败: %v", filepath.Base(path), err)
			continue
		}
		if strings.TrimSpace(a.UserID) == "" || strings.TrimSpace(a.CloudDragonToken) == "" {
			continue
		}
		a.FilePath = path
		a.tasks = true
		if st, ok := states[a.UserID]; ok {
			a.applyState(st)
		}
		accounts = append(accounts, &a)
	}
	m.mu.Lock()
	m.accounts = accounts
	m.mu.Unlock()
	if len(accounts) > 0 {
		log.Printf("[codearts] 已加载 %d 个账号（%s）", len(accounts), m.dir)
	}
}

func (m *Manager) statePath() string {
	return filepath.Join(m.dir, "state.json")
}

func (m *Manager) loadState() map[string]AccountState {
	out := map[string]AccountState{}
	if m.dir == "" {
		return out
	}
	raw, err := safefile.Read(m.statePath(), nil)
	if err != nil {
		return out
	}
	var items []AccountState
	if err := json.Unmarshal(raw, &items); err != nil {
		// Older shape: {"accounts":[...]}.
		var wrapper struct {
			Accounts []AccountState `json:"accounts"`
		}
		if err := json.Unmarshal(raw, &wrapper); err != nil {
			return out
		}
		items = wrapper.Accounts
	}
	for _, it := range items {
		if it.Name != "" {
			out[it.Name] = it
		}
	}
	return out
}

func (m *Manager) saveState() {
	if m == nil || m.dir == "" {
		return
	}
	m.mu.RLock()
	accounts := append([]*Account(nil), m.accounts...)
	m.mu.RUnlock()
	items := make([]AccountState, 0, len(accounts))
	for _, a := range accounts {
		items = append(items, a.state())
	}
	raw, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(m.dir, 0o755); err != nil {
		return
	}
	if err := safefile.Write(m.statePath(), raw, 0o600); err != nil {
		log.Printf("WARN: [codearts] 状态落盘失败: %v", err)
	}
}

func (m *Manager) saveAccount(a *Account) error {
	if a == nil || a.FilePath == "" {
		return errors.New("codearts account has no file path")
	}
	raw, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return safefile.WriteKeep(a.FilePath, raw, 0o600)
}

// Accounts returns panel-facing account views.
func (m *Manager) Accounts() []AccountView {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	accounts := append([]*Account(nil), m.accounts...)
	max := m.cfg.MaxConcurrent
	m.mu.RUnlock()
	out := make([]AccountView, 0, len(accounts))
	for _, a := range accounts {
		out = append(out, a.view(max))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UID < out[j].UID })
	return out
}

// AccountByUID returns the account with the given UID.
func (m *Manager) AccountByUID(uid string) *Account {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, a := range m.accounts {
		if a.UserID == uid {
			return a
		}
	}
	return nil
}

// RemoveAccount deletes the credential file and state entry.
func (m *Manager) RemoveAccount(uid string) error {
	m.mu.Lock()
	idx := -1
	var target *Account
	for i, a := range m.accounts {
		if a.UserID == uid {
			idx, target = i, a
			break
		}
	}
	if idx >= 0 {
		m.accounts = append(m.accounts[:idx], m.accounts[idx+1:]...)
	}
	m.mu.Unlock()
	if target == nil {
		return errors.New("account not found")
	}
	if target.FilePath != "" {
		if err := os.Remove(target.FilePath); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	m.saveState()
	return nil
}

// SetAccountEnabled toggles the operator-disabled flag.
func (m *Manager) SetAccountEnabled(uid string, enabled bool) error {
	a := m.AccountByUID(uid)
	if a == nil {
		return errors.New("account not found")
	}
	if enabled {
		a.manualEnable()
	} else {
		a.manualDisable("手动停用")
	}
	m.saveState()
	return nil
}

// NoteAccountError records a chat failure for an account.
func (m *Manager) NoteAccountError(uid, msg string, soft, terminal bool, cooldown time.Duration) {
	a := m.AccountByUID(uid)
	if a == nil {
		return
	}
	a.noteError(msg, soft, terminal, cooldown)
	m.saveState()
}

// NoteAccountSuccess clears transient failures.
func (m *Manager) NoteAccountSuccess(uid string) {
	a := m.AccountByUID(uid)
	if a == nil {
		return
	}
	a.noteSuccess()
}

func (m *Manager) pick(model string, exclude map[string]bool) *Account {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.accounts) == 0 {
		return nil
	}
	max := m.cfg.MaxConcurrent
	now := time.Now()
	for i := 0; i < len(m.accounts); i++ {
		idx := (m.next + i) % len(m.accounts)
		a := m.accounts[idx]
		if exclude != nil && exclude[a.UserID] {
			continue
		}
		if model != "" && !a.hasModel(model) {
			continue
		}
		if !a.available(now, max) {
			continue
		}
		m.next = (idx + 1) % len(m.accounts)
		return a
	}
	return nil
}

func (m *Manager) busyAccounts(exclude map[string]bool) []*Account {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Account, 0)
	for _, a := range m.accounts {
		if exclude != nil && exclude[a.UserID] {
			continue
		}
		a.mu.Lock()
		cooling := !a.disabled && time.Now().Before(a.coolUntil)
		busy := !a.disabled && !cooling && a.active >= m.cfg.MaxConcurrent
		a.mu.Unlock()
		if busy {
			out = append(out, a)
		}
	}
	return out
}

// addAccount inserts or replaces an account in memory.
func (m *Manager) addAccount(a *Account) {
	if a == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, cur := range m.accounts {
		if cur.UserID == a.UserID {
			m.accounts[i] = a
			return
		}
	}
	m.accounts = append(m.accounts, a)
}

func (m *Manager) httpClient() *http.Client {
	if m == nil || m.http == nil {
		return http.DefaultClient
	}
	return m.http
}

// Models returns the merged CodeArts catalogue (seed fallback when discovery
// fails and no account has a cached list).
func (m *Manager) Models(ctx context.Context) []Model {
	if m == nil || !m.Enabled() {
		return nil
	}
	m.mu.RLock()
	accounts := append([]*Account(nil), m.accounts...)
	m.mu.RUnlock()
	if len(accounts) == 0 {
		return SeedModels()
	}
	seen := map[string]bool{}
	var out []Model
	for _, a := range accounts {
		if a.disabled {
			continue
		}
		models := m.ensureModels(ctx, a, false)
		for _, mi := range models {
			key := strings.ToLower(mi.ID)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, mi)
		}
	}
	if len(out) == 0 {
		return SeedModels()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// RefreshModels forces discovery for every account.
func (m *Manager) RefreshModels(ctx context.Context) error {
	if m == nil || !m.Enabled() {
		return errors.New("CodeArts 出口未启用")
	}
	m.mu.RLock()
	accounts := append([]*Account(nil), m.accounts...)
	m.mu.RUnlock()
	if len(accounts) == 0 {
		return errors.New("没有 CodeArts 账号")
	}
	var lastErr error
	for _, a := range accounts {
		if a.disabled {
			continue
		}
		if err := ensureToken(ctx, m, a); err != nil {
			lastErr = err
			continue
		}
		if models := m.ensureModels(ctx, a, true); len(models) == 0 {
			lastErr = fmt.Errorf("账号 %s 模型目录为空", a.UserID)
		}
	}
	return lastErr
}
