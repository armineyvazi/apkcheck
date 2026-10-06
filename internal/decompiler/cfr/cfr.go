// Package cfr integrates the CFR Java decompiler (optional).
package cfr

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

// Decompiler runs CFR via `cfr` wrapper or `java -jar cfr.jar`.
type Decompiler struct {
	Path     string // cfr binary or jar
	JavaPath string
}

func New(custom, java string) *Decompiler {
	return &Decompiler{Path: custom, JavaPath: java}
}

func (d *Decompiler) Name() string { return "cfr" }

func (d *Decompiler) Available(ctx context.Context) bool {
	_, err := d.Version(ctx)
	return err == nil
}

func (d *Decompiler) Version(ctx context.Context) (string, error) {
	exe, jar, err := d.resolve()
	if err != nil {
		return "", err
	}
	var res *runner.Result
	if jar != "" {
		res, err = runner.Run(ctx, exe, "-jar", jar, "--help")
	} else {
		res, err = runner.Run(ctx, exe, "--help")
	}
	if err != nil && res == nil {
		return "", err
	}
	out := ""
	if res != nil {
		out = res.Stdout + res.Stderr
	}
	// CFR prints version in help header.
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(strings.ToLower(line), "cfr") {
			return line, nil
		}
	}
	if err != nil {
		return "available", nil
	}
	return "available", nil
}

func (d *Decompiler) resolve() (javaOrBin, jar string, err error) {
	if d.Path != "" {
		if strings.HasSuffix(d.Path, ".jar") {
			java := d.JavaPath
			if java == "" {
				java, err = runner.LookPath("", "java")
				if err != nil {
					return "", "", err
				}
			}
			return java, d.Path, nil
		}
		p, err := runner.LookPath(d.Path, "cfr")
		return p, "", err
	}
	if p := os.Getenv("CFR_JAR"); p != "" {
		java, jerr := runner.LookPath(d.JavaPath, "java")
		if jerr != nil {
			return "", "", jerr
		}
		return java, p, nil
	}
	if p, err := runner.LookPath("", "cfr"); err == nil {
		return p, "", nil
	}
	// Common jar locations (including project tools/)
	candidates := []string{
		"cfr.jar",
		"tools/cfr.jar",
		"tools/cfr-0.152.jar",
		"/usr/local/share/cfr/cfr.jar",
		"/opt/cfr/cfr.jar",
	}
	// Resolve relative to executable (…/apkcheck/bin/apkcheck → …/apkcheck/tools/cfr.jar)
	if exe, eerr := os.Executable(); eerr == nil {
		root := filepath.Dir(filepath.Dir(exe)) // bin/../
		candidates = append([]string{
			filepath.Join(root, "tools", "cfr.jar"),
			filepath.Join(root, "tools", "cfr-0.152.jar"),
			filepath.Join(filepath.Dir(exe), "cfr.jar"),
		}, candidates...)
	}
	java, jerr := runner.LookPath(d.JavaPath, "java")
	if jerr != nil {
		return "", "", fmt.Errorf("cfr not found (no cfr binary or cfr.jar)")
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return java, c, nil
		}
	}
	return "", "", fmt.Errorf("cfr not found; place jar at tools/cfr.jar or set --cfr / CFR_JAR")
}

func (d *Decompiler) Decompile(ctx context.Context, input decompiler.Input) (*decompiler.Result, error) {
	exe, jar, err := d.resolve()
	if err != nil {
		return &decompiler.Result{Name: d.Name(), Failed: true, FailReason: err.Error()}, err
	}
	out := filepath.Join(input.OutDir, "cfr")
	if err := os.MkdirAll(out, 0o750); err != nil {
		return nil, err
	}
	ver, _ := d.Version(ctx)
	res := &decompiler.Result{Name: d.Name(), OutDir: out, JavaRoot: out, Version: ver}

	var args []string
	if jar != "" {
		args = []string{"-jar", jar, input.APKPath, "--outputdir", out}
	} else {
		args = []string{input.APKPath, "--outputdir", out}
	}
	if _, err := runner.Run(ctx, exe, args...); err != nil {
		res.Failed = true
		res.FailReason = err.Error()
		res.Notes = append(res.Notes, "cfr decompilation failed")
		return res, nil // optional tool: soft-fail
	}
	methods, err := javaast.ParseDir(out, ir.SourceCFR)
	if err != nil {
		res.Notes = append(res.Notes, err.Error())
	}
	res.MethodIRs = methods
	return res, nil
}
