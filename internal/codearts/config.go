// Package codearts implements Huawei Cloud CodeArts (盘古助手 / 码道) as a
// third upstream for this gateway: OAuth, STS credentials, model discovery and
// OpenAI-compatible chat streaming.
//
// The protocol is ported from the Python implementation in
// niyouqianma/workbuddy2api-hub (wb_codearts.py / wb_codearts_crypto.py), and
// the public integration guide in docs/CodeArts 接入与运行流程.md.
package codearts

import (
	"encoding/json"
	"errors"
	"io/fs"
	"math"
	"os"
	"path/filepath"

	"github.com/misakano7545/workbuddy2api-panel/internal/safefile"
)

// Config is the CodeArts section persisted at <data>/codearts/config.json.
type Config struct {
	Enabled              bool    `json:"enabled"`
	TimeoutSeconds       float64 `json:"timeout_seconds"`
	StreamTimeoutSeconds float64 `json:"stream_timeout_seconds"`
	ModelsTTLSeconds     float64 `json:"models_ttl_seconds"`
	MaxConcurrent        int     `json:"max_concurrent"`
	BusyWaitSeconds      float64 `json:"busy_wait_seconds"`
	BenefitAutoClaim     bool    `json:"benefit_auto_claim"`
	CreditsAutoClaim     bool    `json:"credits_auto_claim"`
}

// DefaultConfig mirrors the documented defaults. The outbound is disabled
// until an operator explicitly enables it.
func DefaultConfig() Config {
	return Config{
		Enabled:              false,
		TimeoutSeconds:       30,
		StreamTimeoutSeconds: 600,
		ModelsTTLSeconds:     300,
		MaxConcurrent:        1,
		BusyWaitSeconds:      10,
		BenefitAutoClaim:     true,
		CreditsAutoClaim:     false,
	}
}

func clampFloat(v, def, low, high float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return def
	}
	if v < low {
		return low
	}
	if v > high {
		return high
	}
	return v
}

// Normalize bounds every numeric field to the documented safe range and
// applies defaults for zero values.
func (c *Config) Normalize() {
	def := DefaultConfig()
	if c.TimeoutSeconds <= 0 {
		c.TimeoutSeconds = def.TimeoutSeconds
	}
	if c.StreamTimeoutSeconds <= 0 {
		c.StreamTimeoutSeconds = def.StreamTimeoutSeconds
	}
	if c.ModelsTTLSeconds <= 0 {
		c.ModelsTTLSeconds = def.ModelsTTLSeconds
	}
	if c.MaxConcurrent <= 0 {
		c.MaxConcurrent = def.MaxConcurrent
	}
	if c.BusyWaitSeconds < 0 {
		c.BusyWaitSeconds = 0
	}
	c.TimeoutSeconds = clampFloat(c.TimeoutSeconds, def.TimeoutSeconds, 1, 600)
	c.StreamTimeoutSeconds = clampFloat(c.StreamTimeoutSeconds, def.StreamTimeoutSeconds, 1, 3600)
	c.ModelsTTLSeconds = clampFloat(c.ModelsTTLSeconds, def.ModelsTTLSeconds, 60, 86400)
	c.BusyWaitSeconds = clampFloat(c.BusyWaitSeconds, def.BusyWaitSeconds, 0, 120)
	if c.MaxConcurrent > 20 {
		c.MaxConcurrent = 20
	}
}

// LoadConfig reads <dir>/config.json. A missing file is not an error.
func LoadConfig(dir string) (Config, error) {
	cfg := DefaultConfig()
	if dir == "" {
		return cfg, nil
	}
	raw, err := safefile.Read(filepath.Join(dir, "config.json"), nil)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return DefaultConfig(), err
	}
	cfg.Normalize()
	return cfg, nil
}

// SaveConfig atomically writes <dir>/config.json.
func SaveConfig(dir string, cfg Config) error {
	if dir == "" {
		return errors.New("codearts data directory is empty")
	}
	cfg.Normalize()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return safefile.Write(filepath.Join(dir, "config.json"), raw, 0o600)
}
