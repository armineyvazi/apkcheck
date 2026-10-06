// Package adb provides a thin, testable wrapper around the adb binary.
// Analysis code depends on this package — not on raw shell strings.
package adb

import (
	"context"
	"fmt"
	"strings"

	"github.com/armin/apkcheck/internal/runner"
	"github.com/armin/apkcheck/internal/runtime/env"
)

// Client talks to a specific adb binary.
type Client struct {
	Path string
}

// New creates a client using discovered or PATH adb.
func New(sdk env.SDK) (*Client, error) {
	if sdk.ADB != "" {
		return &Client{Path: sdk.ADB}, nil
	}
	p, err := runner.LookPath("", "adb")
	if err != nil {
		return nil, fmt.Errorf("adb not found — brew install android-platform-tools or set ANDROID_HOME: %w", err)
	}
	return &Client{Path: p}, nil
}

// Run executes adb with args.
func (c *Client) Run(ctx context.Context, args ...string) (*runner.Result, error) {
	return runner.Run(ctx, c.Path, args...)
}

// SerialRun prefixes -s <serial>.
func (c *Client) SerialRun(ctx context.Context, serial string, args ...string) (*runner.Result, error) {
	full := append([]string{"-s", serial}, args...)
	return c.Run(ctx, full...)
}

// Shell runs adb shell …
func (c *Client) Shell(ctx context.Context, serial string, args ...string) (string, error) {
	full := append([]string{"shell"}, args...)
	res, err := c.SerialRun(ctx, serial, full...)
	if err != nil {
		out := ""
		if res != nil {
			out = res.Stdout + res.Stderr
		}
		return out, err
	}
	return res.Stdout, nil
}

// GetProp reads a device property.
func (c *Client) GetProp(ctx context.Context, serial, key string) (string, error) {
	out, err := c.Shell(ctx, serial, "getprop", key)
	return strings.TrimSpace(out), err
}

// Version returns adb version string.
func (c *Client) Version(ctx context.Context) (string, error) {
	res, err := c.Run(ctx, "version")
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(res.Stdout)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	return line, nil
}
