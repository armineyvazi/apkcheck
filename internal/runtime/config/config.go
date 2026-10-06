// Package config loads apkcheck.yaml runtime settings.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/armin/apkcheck/internal/runtime/scenarios"
)

// File is the root configuration document.
type File struct {
	Runtime RuntimeConfig `yaml:"runtime"`
}

// Duration wraps time.Duration with YAML support for values like "180s".
type Duration time.Duration

// UnmarshalYAML parses "10s", "2m", or integer nanoseconds.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("duration must be a scalar")
	}
	s := strings.TrimSpace(value.Value)
	if s == "" {
		*d = 0
		return nil
	}
	if parsed, err := time.ParseDuration(s); err == nil {
		*d = Duration(parsed)
		return nil
	}
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err == nil {
		*d = Duration(n)
		return nil
	}
	return fmt.Errorf("invalid duration %q", s)
}

// Duration returns the Go time.Duration.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

// RuntimeConfig controls dynamic analysis.
type RuntimeConfig struct {
	Enabled         bool                 `yaml:"enabled"`
	Mode            string               `yaml:"mode"` // auto|device|emulator
	WarnUntrusted   bool                 `yaml:"warn_untrusted"`
	Emulator        EmulatorConfig       `yaml:"emulator"`
	Installation    InstallConfig        `yaml:"installation"`
	Execution       ExecConfig           `yaml:"execution"`
	Logcat          LogcatConfig         `yaml:"logcat"`
	Screenshots     ShotConfig           `yaml:"screenshots"`
	Network         NetworkConfig        `yaml:"network"`
	Instrumentation InstrConfig          `yaml:"instrumentation"`
	Scenarios       []scenarios.Scenario `yaml:"scenarios"`
	Cleanup         CleanupConfig        `yaml:"cleanup"`
}

type EmulatorConfig struct {
	AVD         string   `yaml:"avd"`
	BootTimeout Duration `yaml:"boot_timeout"`
	ColdBoot    bool     `yaml:"cold_boot"`
	Snapshot    string   `yaml:"snapshot"`
}

type InstallConfig struct {
	Reinstall   bool `yaml:"reinstall"`
	ClearData   bool `yaml:"clear_data"`
	SkipInstall bool `yaml:"skip_install"`
}

type ExecConfig struct {
	Launch   bool     `yaml:"launch"`
	Timeout  Duration `yaml:"timeout"` // overall scenario budget (not logcat alone)
	Activity string   `yaml:"activity"`
}

type LogcatConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Raw      bool     `yaml:"raw"`
	Duration Duration `yaml:"duration"` // post-scenario capture window
}

type ShotConfig struct {
	Enabled bool `yaml:"enabled"`
}

type NetworkConfig struct {
	Enabled            bool `yaml:"enabled"`
	CaptureConnections bool `yaml:"capture_connections"`
	MITM               bool `yaml:"mitm"`
}

type InstrConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Provider string `yaml:"provider"`
}

type CleanupConfig struct {
	ClearData    bool `yaml:"clear_data"`
	Uninstall    bool `yaml:"uninstall"`
	Shutdown     bool `yaml:"shutdown"`
	KeepEmulator bool `yaml:"keep_emulator"`
}

// Default returns safe defaults (MITM off, instrumentation off).
func Default() RuntimeConfig {
	return RuntimeConfig{
		Enabled: true, Mode: "auto", WarnUntrusted: true,
		Emulator:     EmulatorConfig{BootTimeout: Duration(360 * time.Second)},
		Installation: InstallConfig{Reinstall: true},
		Execution:    ExecConfig{Launch: true, Timeout: Duration(120 * time.Second)},
		Logcat:       LogcatConfig{Enabled: true, Raw: true, Duration: Duration(20 * time.Second)},
		Network:      NetworkConfig{Enabled: true, CaptureConnections: true, MITM: false},
		Cleanup:      CleanupConfig{KeepEmulator: true},
		Scenarios: []scenarios.Scenario{{
			Name:    "startup",
			Actions: []scenarios.Action{{Launch: true}, {Wait: 10 * time.Second}},
		}},
	}
}

// Load reads YAML or returns defaults.
func Load(path string) (RuntimeConfig, error) {
	cfg := Default()
	if path == "" {
		var err error
		path, err = FindDefault()
		if err != nil {
			return cfg, nil
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	var f File
	f.Runtime = Default()
	if err := yaml.Unmarshal(data, &f); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}
	if f.Runtime.Network.MITM {
		f.Runtime.Network.MITM = false
	}
	if f.Runtime.Logcat.Duration == 0 {
		f.Runtime.Logcat.Duration = Duration(20 * time.Second)
	}
	if f.Runtime.Emulator.BootTimeout == 0 {
		f.Runtime.Emulator.BootTimeout = Duration(360 * time.Second)
	}
	return f.Runtime, nil
}

// FindDefault locates apkcheck.yaml.
func FindDefault() (string, error) {
	cands := []string{"configs/apkcheck.yaml", "apkcheck.yaml"}
	if exe, err := os.Executable(); err == nil {
		root := filepath.Dir(filepath.Dir(exe))
		cands = append([]string{filepath.Join(root, "configs", "apkcheck.yaml")}, cands...)
	}
	if v := os.Getenv("APKCHECK_CONFIG"); v != "" {
		cands = append([]string{v}, cands...)
	}
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c, nil
		}
	}
	return "", fmt.Errorf("apkcheck.yaml not found")
}
