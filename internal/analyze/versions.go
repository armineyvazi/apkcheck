package analyze

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/armin/apkcheck/internal/androidx"
	"github.com/armin/apkcheck/internal/apk"
	"github.com/armin/apkcheck/internal/decompiler"
	"github.com/armin/apkcheck/internal/decompiler/apktool"
	"github.com/armin/apkcheck/internal/diff"
	"github.com/armin/apkcheck/internal/doctor"
	"github.com/armin/apkcheck/internal/ir"
	"github.com/armin/apkcheck/internal/registry"
	"github.com/armin/apkcheck/internal/versioncmp"
	"github.com/armin/apkcheck/internal/versioned"
)

// VersionCompareConfig configures compare-versions.
type VersionCompareConfig struct {
	Config
	VersionsFile string
}

// CompareVersions runs every enabled pin against the same APK and diffs vs Smali.
func CompareVersions(ctx context.Context, cfg VersionCompareConfig) (*versioncmp.Report, []registry.ToolIdentity, error) {
	a := New(cfg.Config)
	ctx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
	defer cancel()

	fmt.Fprintf(os.Stderr, "APKCheck v%s — version matrix\n\n", Version)

	if _, err := apk.Inspect(a.cfg.APKPath); err != nil {
		return nil, nil, err
	}

	path := cfg.VersionsFile
	var err error
	if path == "" {
		path, err = registry.FindDefault()
		if err != nil {
			return nil, nil, err
		}
	}
	vcfg, err := registry.Load(path)
	if err != nil {
		return nil, nil, err
	}
	root := registry.ProjectRoot()
	instances, pins, err := versioned.BuildInstances(vcfg, a.cfg.Paths, root)
	if err != nil {
		return nil, nil, err
	}
	if len(instances) == 0 {
		return nil, pins, fmt.Errorf("no enabled decompiler versions in %s", path)
	}

	fmt.Fprintf(os.Stderr, "Version matrix: %s (%d pins)\n", path, len(instances))
	for _, p := range pins {
		mark := "·"
		if p.Verified {
			mark = "✓"
		} else if p.SHA256 != "" {
			mark = "⚠"
		}
		fmt.Fprintf(os.Stderr, "  %s %s@%s  %s\n", mark, p.Tool, p.Version, p.VerifyNote)
	}
	fmt.Fprintln(os.Stderr)

	tools := doctor.Check(ctx, a.cfg.Paths)
	if !tools.OK {
		return nil, pins, fmt.Errorf("required host tools missing — run apkcheck doctor")
	}

	workDir := filepath.Join(a.cfg.OutputDir, "work-versions")
	_ = os.MkdirAll(workDir, 0o750)

	at := apktool.New(a.cfg.Paths.Apktool)
	decode, err := at.Decode(ctx, a.cfg.APKPath, workDir)
	if err != nil {
		return nil, pins, fmt.Errorf("apktool: %w", err)
	}

	smaliMethods := selectMethods(a, decode.Methods)

	byKey := map[string]map[string][]*ir.MethodIR{}
	for _, inst := range instances {
		fmt.Fprintf(os.Stderr, "Running %s …\n", inst.Key())
		if !inst.Available(ctx) {
			fmt.Fprintf(os.Stderr, "  skip (unavailable)\n")
			byKey[inst.Key()] = map[string][]*ir.MethodIR{}
			continue
		}
		res, err := inst.Decompile(ctx, decompiler.Input{
			APKPath: a.cfg.APKPath,
			OutDir:  workDir,
			Workers: a.cfg.Workers,
		})
		if err != nil || res == nil {
			fmt.Fprintf(os.Stderr, "  failed: %v\n", err)
			byKey[inst.Key()] = map[string][]*ir.MethodIR{}
			continue
		}
		if res.Failed {
			fmt.Fprintf(os.Stderr, "  soft-fail: %s\n", res.FailReason)
		}
		byKey[inst.Key()] = diff.IndexByFuzzyKey(res.MethodIRs)
		fmt.Fprintf(os.Stderr, "  ✓ %d methods parsed\n", len(res.MethodIRs))
	}

	return versioncmp.Compare(smaliMethods, byKey), pins, nil
}

func selectMethods(a *Analyzer, methods []*ir.MethodIR) []*ir.MethodIR {
	out := make([]*ir.MethodIR, 0, len(methods))
	for _, m := range methods {
		if m == nil {
			continue
		}
		if !a.cfg.IncludeEmpty && isEmptyMethod(m) {
			continue
		}
		if a.cfg.SkipFramework && androidx.IsFrameworkPackage(m.ClassName) {
			continue
		}
		if a.cfg.SkipSynthetic && androidx.IsKotlinSynthetic(m.ClassName, m.MethodName) {
			continue
		}
		out = append(out, m)
	}
	if a.cfg.ClassFilter != "" || a.cfg.MethodFilter != "" {
		out = filterMethods(out, a.cfg.ClassFilter, a.cfg.MethodFilter)
	}
	if a.cfg.Limit > 0 && len(out) > a.cfg.Limit {
		out = prioritize(out, a.cfg.Limit)
	}
	return out
}
