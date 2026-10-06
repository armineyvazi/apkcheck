// Package workspace provides Lab workspace maintenance helpers (reset / fresh start).
package workspace

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResetOptions selects which workspace subtrees to wipe before a fresh run.
type ResetOptions struct {
	Sessions     bool `json:"sessions"`
	Recordings   bool `json:"recordings"`
	Logs         bool `json:"logs"`
	Runs         bool `json:"runs"` // pipeline validate runs/
	SecurityRuns bool `json:"security_runs"`
	Observations bool `json:"observations"`
	ProxyFlows   bool `json:"proxy_flows"` // mitm flow dumps / jsonl (keeps CA)
	Exports      bool `json:"exports"`
}

// FreshRunReset wipes prior test evidence so the next scenario starts clean.
// APKs, projects, builds, certs, and scenarios are kept.
func FreshRunReset() ResetOptions {
	return ResetOptions{
		Sessions: true, Recordings: true, Logs: true, Runs: true,
		SecurityRuns: true, Observations: true, ProxyFlows: true, Exports: false,
	}
}

// Reset applies opts under root. Returns deleted top-level paths.
// Wipe clears directory *contents* (and recreates the dir) so bind-mount
// ownership of the parent workspace root does not block reset.
func Reset(root string, opts ResetOptions) ([]string, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("workspace root required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	var removed []string
	wipe := func(rel string) error {
		p := filepath.Join(abs, rel)
		if err := os.MkdirAll(p, 0o750); err != nil {
			return fmt.Errorf("ensure %s: %w", rel, err)
		}
		entries, err := os.ReadDir(p)
		if err != nil {
			return fmt.Errorf("read %s: %w", rel, err)
		}
		for _, e := range entries {
			target := filepath.Join(p, e.Name())
			if err := os.RemoveAll(target); err != nil {
				return fmt.Errorf("remove %s/%s: %w", rel, e.Name(), err)
			}
		}
		removed = append(removed, rel)
		return nil
	}
	if opts.Sessions {
		if err := wipe("sessions"); err != nil {
			return removed, err
		}
	}
	if opts.Recordings {
		if err := wipe("recordings"); err != nil {
			return removed, err
		}
	}
	if opts.Logs {
		if err := wipe("logs"); err != nil {
			return removed, err
		}
	}
	if opts.Runs {
		if err := wipe("runs"); err != nil {
			return removed, err
		}
	}
	if opts.SecurityRuns {
		if err := wipe("security-runs"); err != nil {
			return removed, err
		}
	}
	if opts.Observations {
		if err := wipe("observations"); err != nil {
			return removed, err
		}
	}
	if opts.Exports {
		if err := wipe("exports"); err != nil {
			return removed, err
		}
	}
	if opts.ProxyFlows {
		proxyDir := filepath.Join(abs, "proxy")
		for _, name := range []string{"flows.mitm", "flows.jsonl", "mitm.log"} {
			p := filepath.Join(proxyDir, name)
			_ = os.Remove(p)
			removed = append(removed, filepath.Join("proxy", name))
		}
	}
	return removed, nil
}
