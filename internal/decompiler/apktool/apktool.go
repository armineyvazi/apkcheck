// Package apktool integrates Apktool for Smali and decoded manifest/resources.
package apktool

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/armin/apkcheck/internal/ir"
	"github.com/armin/apkcheck/internal/runner"
	"github.com/armin/apkcheck/internal/smali"
)

// Tool wraps Apktool.
type Tool struct {
	Path string
}

// New creates an Apktool wrapper.
func New(custom string) *Tool {
	return &Tool{Path: custom}
}

func (t *Tool) Name() string { return "apktool" }

func (t *Tool) resolve() (string, error) {
	return runner.LookPath(t.Path, "apktool")
}

func (t *Tool) Available(ctx context.Context) bool {
	_, err := t.Version(ctx)
	return err == nil
}

func (t *Tool) Version(ctx context.Context) (string, error) {
	path, err := t.resolve()
	if err != nil {
		return "", err
	}
	res, err := runner.Run(ctx, path, "-version")
	if err != nil {
		res2, err2 := runner.Run(ctx, path, "--version")
		if err2 != nil {
			return "", err
		}
		return strings.TrimSpace(firstLine(res2.Stdout + res2.Stderr)), nil
	}
	return strings.TrimSpace(firstLine(res.Stdout + res.Stderr)), nil
}

// DecodeResult is the output of apktool d.
type DecodeResult struct {
	OutDir     string
	SmaliRoots []string
	Manifest   string
	Methods    []*ir.MethodIR
	Version    string
	Failed     bool
	FailReason string
}

// Decode runs `apktool d` and parses Smali.
func (t *Tool) Decode(ctx context.Context, apkPath, outDir string) (*DecodeResult, error) {
	path, err := t.resolve()
	if err != nil {
		return &DecodeResult{Failed: true, FailReason: err.Error()}, err
	}
	dest := filepath.Join(outDir, "apktool")
	if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
		return nil, err
	}
	// Remove prior decode to avoid apktool interactive prompt.
	_ = os.RemoveAll(dest)

	ver, _ := t.Version(ctx)
	res := &DecodeResult{OutDir: dest, Version: ver}

	args := []string{"d", "-f", "-o", dest, apkPath}
	if _, err := runner.Run(ctx, path, args...); err != nil {
		res.Failed = true
		res.FailReason = err.Error()
		return res, err
	}

	manifestPath := filepath.Join(dest, "AndroidManifest.xml")
	if data, err := os.ReadFile(manifestPath); err == nil {
		res.Manifest = string(data)
	}

	roots := findSmaliRoots(dest)
	res.SmaliRoots = roots
	for _, root := range roots {
		ms, err := smali.ParseDir(root)
		if err != nil {
			return res, fmt.Errorf("parse smali under %s: %w", root, err)
		}
		res.Methods = append(res.Methods, ms...)
	}
	return res, nil
}

func findSmaliRoots(root string) []string {
	var roots []string
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if name == "smali" || strings.HasPrefix(name, "smali_") {
			roots = append(roots, filepath.Join(root, name))
		}
	}
	return roots
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}
