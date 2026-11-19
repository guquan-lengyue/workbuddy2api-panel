package codearts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagerConfigAndSeeds(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)
	if m.Enabled() {
		t.Fatal("CodeArts must default to disabled")
	}
	cfg := DefaultConfig()
	cfg.Enabled = true
	if err := m.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	if !m.Enabled() {
		t.Fatal("enabled config not applied")
	}
	models := m.Models(t.Context())
	if len(models) == 0 {
		t.Fatal("seed models missing")
	}
	if len(m.Accounts()) != 0 {
		t.Fatal("fresh manager should have no accounts")
	}
	start, err := m.OAuthStart(7863)
	if err != nil {
		t.Fatal(err)
	}
	if start.AuthURL == "" || !strings.Contains(start.AuthURL, "code_challenge=") ||
		!strings.Contains(start.AuthURL, "ticket_id=") {
		t.Fatalf("bad auth URL: %s", start.AuthURL)
	}
	status, err := m.OAuthPoll(start.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != "pending" {
		t.Fatalf("status = %q", status.Status)
	}
}

func TestManagerLoadsAccountFile(t *testing.T) {
	dir := t.TempDir()
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	auth := map[string]any{
		"user_id":            "u-test",
		"user_name":          "测试账号",
		"cloud_dragon_token": "tok",
		"access_key_id":      "ak",
		"secret_access_key":  "sk",
		"refresh_token":      "rt",
		"dpop_private_key":   PrivateJWK(key),
	}
	raw, _ := json.Marshal(auth)
	if err := os.WriteFile(filepath.Join(dir, "codearts-u-test.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewManager(dir)
	accounts := m.Accounts()
	if len(accounts) != 1 || accounts[0].UID != "u-test" {
		t.Fatalf("accounts = %#v", accounts)
	}
	if err := m.SetAccountEnabled("u-test", false); err != nil {
		t.Fatal(err)
	}
	if !m.Accounts()[0].Disabled {
		t.Fatal("account should be disabled")
	}
	if err := m.SetAccountEnabled("u-test", true); err != nil {
		t.Fatal(err)
	}
	if m.Accounts()[0].Disabled {
		t.Fatal("account should be enabled")
	}
	if err := m.RemoveAccount("u-test"); err != nil {
		t.Fatal(err)
	}
	if len(m.Accounts()) != 0 {
		t.Fatal("account was not removed")
	}
}
