// Package doctor checks external tool availability and version-matrix pins.
package doctor

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/armin/apkcheck/internal/decompiler"
	"github.com/armin/apkcheck/internal/decompiler/apktool"
	"github.com/armin/apkcheck/internal/decompiler/cfr"
	"github.com/armin/apkcheck/internal/decompiler/fernflower"
	"github.com/armin/apkcheck/internal/decompiler/jadx"
	"github.com/armin/apkcheck/internal/registry"
	"github.com/armin/apkcheck/internal/runner"
	"github.com/armin/apkcheck/pkg/model"
)

// Check reports tool availability.
func Check(ctx context.Context, paths decompiler.Paths) *model.DoctorReport {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	report := &model.DoctorReport{OK: true}

	check := func(name string, required bool, fn func(context.Context) (string, string, error)) {
		ver, path, err := fn(ctx)
		st := model.ToolStatus{Name: name, Required: required, Path: path, Version: ver}
		if err != nil {
			st.Available = false
			st.Error = err.Error()
			if required {
				report.OK = false
			}
		} else {
			st.Available = true
		}
		report.Tools = append(report.Tools, st)
	}

	check("Java", true, func(ctx context.Context) (string, string, error) {
		p, err := runner.LookPath(paths.Java, "java")
		if err != nil {
			return "", "", err
		}
		res, err := runner.Run(ctx, p, "-version")
		out := ""
		if res != nil {
			out = res.Stderr
			if out == "" {
				out = res.Stdout
			}
		}
		return firstLine(out), p, err
	})

	j := jadx.New(paths.JADX)
	check("JADX", true, func(ctx context.Context) (string, string, error) {
		v, err := j.Version(ctx)
		p, _ := runner.LookPath(paths.JADX, "jadx")
		return v, p, err
	})

	a := apktool.New(paths.Apktool)
	check("Apktool", true, func(ctx context.Context) (string, string, error) {
		v, err := a.Version(ctx)
		p, _ := runner.LookPath(paths.Apktool, "apktool")
		return v, p, err
	})

	c := cfr.New(paths.CFR, paths.Java)
	check("CFR", false, func(ctx context.Context) (string, string, error) {
		v, err := c.Version(ctx)
		return v, paths.CFR, err
	})

	f := fernflower.New(paths.FernFlower, paths.Java)
	check("FernFlower", false, func(ctx context.Context) (string, string, error) {
		v, err := f.Version(ctx)
		path := paths.FernFlower
		if req, rerr := f.ResolveJava(ctx); rerr == nil {
			if req.JarPath != "" {
				path = req.JarPath
			}
			if path == "" {
				path = req.JavaPath
			}
		}
		return v, path, err
	})

	check("ADB", false, func(ctx context.Context) (string, string, error) {
		p, err := runner.LookPath("", "adb")
		if err != nil {
			return "", "", err
		}
		res, err := runner.Run(ctx, p, "version")
		out := ""
		if res != nil {
			out = firstLine(res.Stdout + res.Stderr)
		}
		return out, p, err
	})

	check("Docker", false, func(ctx context.Context) (string, string, error) {
		p, err := runner.LookPath("", "docker")
		if err != nil {
			return "", "", err
		}
		res, err := runner.Run(ctx, p, "version", "--format", "{{.Server.Version}}")
		ver := "available"
		if res != nil {
			if s := strings.TrimSpace(res.Stdout); s != "" {
				ver = s
			}
		}
		return ver, p, err
	})

	// Version matrix pins (informational).
	if path, err := registry.FindDefault(); err == nil {
		if cfg, err := registry.Load(path); err == nil {
			root := registry.ProjectRoot()
			for _, tool := range []string{"jadx", "cfr", "fernflower"} {
				for _, pin := range cfg.EnabledVersions(tool) {
					id := pin.Identity(tool, root)
					name := fmt.Sprintf("pin:%s@%s", tool, pin.ID)
					st := model.ToolStatus{
						Name: name, Required: false, Available: id.Verified || id.SHA256 == "",
						Version: id.VerifyNote, Path: id.Path,
					}
					if id.SHA256 != "" && !id.Verified {
						st.Available = false
						st.Error = id.VerifyNote
					}
					report.Tools = append(report.Tools, st)
				}
			}
		}
	}

	return report
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}
