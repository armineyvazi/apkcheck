// Package registry loads the pinned decompiler version matrix from YAML.
//
// Versions are never hard-coded in Go. Adding a pin means editing the YAML
// and verifying the artifact SHA-256 — never silently downloading "latest".
package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the root version-matrix document.
type Config struct {
	Java        JavaConfig            `yaml:"java"`
	Defaults    Defaults              `yaml:"defaults"`
	Decompilers map[string]ToolFamily `yaml:"decompilers"`
	Apktool     ToolFamily            `yaml:"apktool"`
}

type JavaConfig struct {
	Default string `yaml:"default"`
}

type Defaults struct {
	EnableVersionMatrix bool     `yaml:"enable_version_matrix"`
	Runners             []string `yaml:"runners"`
}

// ToolFamily groups pinned versions of one tool.
type ToolFamily struct {
	Versions []PinnedVersion `yaml:"versions"`
}

// PinnedVersion is a reproducible tool pin.
type PinnedVersion struct {
	ID          string `yaml:"id" json:"version"`
	Note        string `yaml:"note,omitempty" json:"note,omitempty"`
	Source      string `yaml:"source" json:"source"`
	SHA256      string `yaml:"sha256" json:"sha256"`
	Java        string `yaml:"java" json:"java"`
	Runner      string `yaml:"runner" json:"runner"` // local | docker
	Path        string `yaml:"path,omitempty" json:"path,omitempty"`
	Binary      string `yaml:"binary,omitempty" json:"binary,omitempty"`
	DockerImage string `yaml:"docker_image,omitempty" json:"docker_image,omitempty"`
	// Enabled defaults to true when omitted from YAML (pointer distinguishes unset).
	Enabled *bool  `yaml:"enabled" json:"enabled"`
	Config  string `yaml:"config,omitempty" json:"config,omitempty"`
}

// IsEnabled reports whether the pin should run. Omitted YAML enabled ⇒ true.
func (v PinnedVersion) IsEnabled() bool {
	if v.Enabled == nil {
		return true
	}
	return *v.Enabled
}

// ToolIdentity is the recorded identity used in reports.
type ToolIdentity struct {
	Tool        string `json:"tool"`
	Version     string `json:"version"`
	SHA256      string `json:"sha256,omitempty"`
	Java        string `json:"java,omitempty"`
	Source      string `json:"source,omitempty"`
	Runner      string `json:"runner,omitempty"`
	DockerImage string `json:"docker_image,omitempty"`
	Path        string `json:"path,omitempty"`
	Verified    bool   `json:"verified"`
	VerifyNote  string `json:"verify_note,omitempty"`
}

// Load reads and validates a versions.yaml file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read version matrix %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse version matrix: %w", err)
	}
	if cfg.Decompilers == nil {
		cfg.Decompilers = map[string]ToolFamily{}
	}
	return &cfg, nil
}

// FindDefault looks for configs/versions.yaml relative to the executable or cwd.
func FindDefault() (string, error) {
	candidates := []string{
		"configs/versions.yaml",
		filepath.Join(".", "configs", "versions.yaml"),
	}
	if exe, err := os.Executable(); err == nil {
		root := filepath.Dir(filepath.Dir(exe))
		candidates = append([]string{
			filepath.Join(root, "configs", "versions.yaml"),
			filepath.Join(filepath.Dir(exe), "configs", "versions.yaml"),
		}, candidates...)
	}
	if env := os.Getenv("APKCHECK_VERSIONS"); env != "" {
		candidates = append([]string{env}, candidates...)
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c, nil
		}
	}
	return "", fmt.Errorf("version matrix not found (set APKCHECK_VERSIONS or place configs/versions.yaml)")
}

// EnabledVersions returns enabled pins for a tool family name.
func (c *Config) EnabledVersions(tool string) []PinnedVersion {
	fam, ok := c.Decompilers[strings.ToLower(tool)]
	if !ok {
		return nil
	}
	var out []PinnedVersion
	for _, v := range fam.Versions {
		if v.IsEnabled() {
			out = append(out, v)
		}
	}
	return out
}

// Identity builds a ToolIdentity and optionally verifies the on-disk artifact.
func (v PinnedVersion) Identity(tool, projectRoot string) ToolIdentity {
	id := ToolIdentity{
		Tool:        tool,
		Version:     v.ID,
		SHA256:      v.SHA256,
		Java:        v.Java,
		Source:      v.Source,
		Runner:      v.Runner,
		DockerImage: v.DockerImage,
		Path:        resolvePath(projectRoot, v.Path),
	}
	if v.SHA256 == "" {
		id.Verified = false
		id.VerifyNote = "no sha256 pin (host/path tool); not fully reproducible"
		return id
	}
	path := id.Path
	if path == "" {
		id.Verified = false
		id.VerifyNote = "pinned sha256 but path empty"
		return id
	}
	sum, err := FileSHA256(path)
	if err != nil {
		id.Verified = false
		id.VerifyNote = err.Error()
		return id
	}
	if !strings.EqualFold(sum, v.SHA256) {
		id.Verified = false
		id.VerifyNote = fmt.Sprintf("sha256 mismatch: got %s want %s", sum, v.SHA256)
		return id
	}
	id.Verified = true
	id.VerifyNote = "sha256 verified"
	return id
}

func resolvePath(root, p string) string {
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return p
	}
	if root != "" {
		return filepath.Join(root, p)
	}
	return p
}

// FileSHA256 returns the hex SHA-256 of a file.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open for hash: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ProjectRoot guesses the apkcheck project root from the executable or cwd.
func ProjectRoot() string {
	if exe, err := os.Executable(); err == nil {
		root := filepath.Dir(filepath.Dir(exe))
		if st, err := os.Stat(filepath.Join(root, "configs")); err == nil && st.IsDir() {
			return root
		}
	}
	cwd, _ := os.Getwd()
	return cwd
}
