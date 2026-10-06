// Package jadx integrates the JADX CLI decompiler.
package jadx

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/armin/apkcheck/internal/decompiler"
	"github.com/armin/apkcheck/internal/ir"
	"github.com/armin/apkcheck/internal/parser/javaast"
	"github.com/armin/apkcheck/internal/runner"
)

// Decompiler runs JADX.
type Decompiler struct {
	Path string
}

// New creates a JADX decompiler using path or PATH lookup.
func New(custom string) *Decompiler {
	return &Decompiler{Path: custom}
}

func (d *Decompiler) Name() string { return "jadx" }

func (d *Decompiler) resolve() (string, error) {
	return runner.LookPath(d.Path, "jadx")
}

func (d *Decompiler) Available(ctx context.Context) bool {
	_, err := d.Version(ctx)
	return err == nil
}

func (d *Decompiler) Version(ctx context.Context) (string, error) {
	path, err := d.resolve()
	if err != nil {
		return "", err
	}
	res, err := runner.Run(ctx, path, "--version")
	if err != nil {
		// some builds use -v
		res2, err2 := runner.Run(ctx, path, "-v")
		if err2 != nil {
			return "", err
		}
		return strings.TrimSpace(firstLine(res2.Stdout + res2.Stderr)), nil
	}
	v := strings.TrimSpace(firstLine(res.Stdout + res.Stderr))
	if v == "" {
		v = "available"
	}
	return v, nil
}

func (d *Decompiler) Decompile(ctx context.Context, input decompiler.Input) (*decompiler.Result, error) {
	path, err := d.resolve()
	if err != nil {
		return &decompiler.Result{Name: d.Name(), Failed: true, FailReason: err.Error()}, err
	}
	out := filepath.Join(input.OutDir, "jadx")
	if err := os.MkdirAll(out, 0o750); err != nil {
		return nil, fmt.Errorf("mkdir jadx out: %w", err)
	}
	ver, _ := d.Version(ctx)

	args := []string{
		"--deobf",
		"--show-bad-code",
		"--no-res",
		"-d", out,
		input.APKPath,
	}
	if input.Workers > 0 {
		args = append([]string{"-j", fmt.Sprintf("%d", input.Workers)}, args...)
	}

	res := &decompiler.Result{
		Name:     d.Name(),
		OutDir:   out,
		JavaRoot: out,
		Version:  ver,
	}
	if _, err := runner.Run(ctx, path, args...); err != nil {
		res.Failed = true
		res.FailReason = err.Error()
		res.Notes = append(res.Notes, "jadx decompilation failed; any partial output may still be parsed")
		// Attempt partial parse below.
	}

	sources := out
	// JADX may put sources under sources/
	if st, err := os.Stat(filepath.Join(out, "sources")); err == nil && st.IsDir() {
		sources = filepath.Join(out, "sources")
		res.JavaRoot = sources
	}
	methods, err := javaast.ParseDir(sources, ir.SourceJADX)
	if err != nil {
		res.Notes = append(res.Notes, fmt.Sprintf("java parse: %v", err))
	}
	res.MethodIRs = methods
	return res, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}
