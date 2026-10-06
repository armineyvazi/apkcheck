// Package runner executes external tools safely with context and timeouts.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Result is the outcome of a subprocess.
type Result struct {
	Path     string
	Args     []string
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
}

// Run executes path with args. It never uses a shell.
func Run(ctx context.Context, path string, args ...string) (*Result, error) {
	return RunEnv(ctx, nil, path, args...)
}

// RunEnv is like Run but prepends extra KEY=VALUE entries to the process environment.
func RunEnv(ctx context.Context, env []string, path string, args ...string) (*Result, error) {
	if path == "" {
		return nil, errors.New("empty executable path")
	}
	start := time.Now()
	cmd := exec.CommandContext(ctx, path, args...)
	if len(env) > 0 {
		cmd.Env = append(append([]string{}, os.Environ()...), env...)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	res := &Result{
		Path:     path,
		Args:     append([]string{}, args...),
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: time.Since(start),
	}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return res, fmt.Errorf("run %s: timeout: %w", path, ctx.Err())
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			return res, fmt.Errorf("run %s: canceled: %w", path, ctx.Err())
		}
		return res, fmt.Errorf("run %s %s: %w\nstderr: %s", path, strings.Join(args, " "), err, truncate(res.Stderr, 2<<10))
	}
	return res, nil
}

// LookPath resolves an executable, optionally preferring customPath.
// Absolute or relative filesystem paths are accepted without PATH lookup.
func LookPath(customPath, name string) (string, error) {
	if customPath != "" {
		if filepath.IsAbs(customPath) || strings.ContainsRune(customPath, os.PathSeparator) {
			st, err := os.Stat(customPath)
			if err != nil {
				return "", fmt.Errorf("custom %s path %q: %w", name, customPath, err)
			}
			if st.IsDir() {
				return "", fmt.Errorf("custom %s path %q is a directory", name, customPath)
			}
			return customPath, nil
		}
		if _, err := exec.LookPath(customPath); err != nil {
			return "", fmt.Errorf("custom %s path %q: %w", name, customPath, err)
		}
		return customPath, nil
	}
	p, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s not found in PATH: %w", name, err)
	}
	return p, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
