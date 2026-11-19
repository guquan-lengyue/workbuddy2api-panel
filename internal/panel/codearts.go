package panel

import (
	"context"
	_ "embed"
	"encoding/json"
	"net/http"

	"github.com/misakano7545/workbuddy2api-panel/internal/codearts"
)

//go:embed codearts_page.html
var codeartsPageHTML []byte

//go:embed codearts_page.js
var codeartsPageJS []byte

// codeartsReady returns the manager or writes a 501/403 response.
func (p *Panel) codeartsReady(w http.ResponseWriter) *codearts.Manager {
	if p.cfg.CodeArts == nil {
		writeErr(w, http.StatusNotImplemented, "codearts not available")
		return nil
	}
	return p.cfg.CodeArts
}

func (p *Panel) codeartsPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(codeartsPageHTML)
}

func (p *Panel) codeartsScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	_, _ = w.Write(codeartsPageJS)
}

func (p *Panel) codeartsStatus(w http.ResponseWriter, r *http.Request) {
	mgr := p.codeartsReady(w)
	if mgr == nil {
		return
	}
	models := mgr.Models(context.Background())
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"config":      mgr.Config(),
		"accounts":    mgr.Accounts(),
		"models":      models,
		"model_count": len(models),
	})
}

func (p *Panel) codeartsConfig(w http.ResponseWriter, r *http.Request) {
	mgr := p.codeartsReady(w)
	if mgr == nil {
		return
	}
	cfg := mgr.Config()
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&cfg); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if err := mgr.Configure(cfg); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "config": mgr.Config()})
}

func (p *Panel) codeartsOAuthStart(w http.ResponseWriter, r *http.Request) {
	mgr := p.codeartsReady(w)
	if mgr == nil {
		return
	}
	res, err := mgr.OAuthStart(0)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (p *Panel) codeartsOAuthPoll(w http.ResponseWriter, r *http.Request) {
	mgr := p.codeartsReady(w)
	if mgr == nil {
		return
	}
	status, err := mgr.OAuthPoll(r.URL.Query().Get("session"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (p *Panel) codeartsRefreshModels(w http.ResponseWriter, r *http.Request) {
	mgr := p.codeartsReady(w)
	if mgr == nil {
		return
	}
	if err := mgr.RefreshModels(r.Context()); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (p *Panel) codeartsAccountEnable(w http.ResponseWriter, r *http.Request) {
	mgr := p.codeartsReady(w)
	if mgr == nil {
		return
	}
	uid := r.PathValue("uid")
	if err := mgr.SetAccountEnabled(uid, true); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (p *Panel) codeartsAccountDisable(w http.ResponseWriter, r *http.Request) {
	mgr := p.codeartsReady(w)
	if mgr == nil {
		return
	}
	uid := r.PathValue("uid")
	if err := mgr.SetAccountEnabled(uid, false); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (p *Panel) codeartsAccountRemove(w http.ResponseWriter, r *http.Request) {
	mgr := p.codeartsReady(w)
	if mgr == nil {
		return
	}
	uid := r.PathValue("uid")
	if err := mgr.RemoveAccount(uid); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
