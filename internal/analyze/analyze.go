// Package analyze orchestrates APK inspection, decompilation, and comparison.
package analyze

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/armin/apkcheck/internal/androidx"
	"github.com/armin/apkcheck/internal/apk"
	"github.com/armin/apkcheck/internal/bundle"
	"github.com/armin/apkcheck/internal/cache"
	"github.com/armin/apkcheck/internal/decompiler"
	"github.com/armin/apkcheck/internal/decompiler/apktool"
	"github.com/armin/apkcheck/internal/decompiler/cfr"
	"github.com/armin/apkcheck/internal/decompiler/fernflower"
	"github.com/armin/apkcheck/internal/decompiler/jadx"
	"github.com/armin/apkcheck/internal/diff"
	"github.com/armin/apkcheck/internal/doctor"
	"github.com/armin/apkcheck/internal/enrich"
	"github.com/armin/apkcheck/internal/ir"
	"github.com/armin/apkcheck/internal/security"
	"github.com/armin/apkcheck/pkg/model"
)

// Version is the apkcheck tool version.
const Version = "0.6.1"

// Config controls an analysis run.
type Config struct {
	APKPath       string
	OutputDir     string
	Workers       int
	KeepTemp      bool
	Verbose       bool
	Focus         string // "", "security"
	Decompilers   []string
	ClassFilter   string
	MethodFilter  string
	Paths         decompiler.Paths
	Timeout       time.Duration
	UseCache      bool
	Limit         int  // max methods to compare (0 = all after filters)
	SkipFramework bool // skip android/androidx/kotlin/java framework packages
	SkipSynthetic bool // skip obvious Kotlin/R8 synthetic methods
	IncludeEmpty  bool // include abstract/native/empty methods
	Logger        *slog.Logger
}

// Analyzer performs cross-decompiler analysis.
type Analyzer struct {
	cfg Config
	log *slog.Logger
}

// New creates an Analyzer.
func New(cfg Config) *Analyzer {
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Minute
	}
	if cfg.OutputDir == "" {
		cfg.OutputDir = "./analysis"
	}
	// Sensible default for interactive use: skip framework noise.
	// Explicit --class/--method filters disable this automatically in CLI.
	log := cfg.Logger
	if log == nil {
		level := slog.LevelInfo
		if cfg.Verbose {
			level = slog.LevelDebug
		}
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	}
	if len(cfg.Decompilers) == 0 {
		cfg.Decompilers = []string{"jadx", "cfr", "fernflower"}
	}
	return &Analyzer{cfg: cfg, log: log}
}

// Analyze runs the full pipeline.
func (a *Analyzer) Analyze(ctx context.Context) (*model.AnalysisResult, error) {
	ctx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
	defer cancel()

	progress := func(step, total int, msg, status string) {
		fmt.Fprintf(os.Stderr, "[%d/%d] %-28s %s\n", step, total, msg, status)
	}

	totalSteps := 7
	progress(1, totalSteps, "Resolving package", "…")
	resolved, err := bundle.Resolve(a.cfg.APKPath, a.cfg.OutputDir)
	if err != nil {
		progress(1, totalSteps, "Resolving package", "✗")
		return nil, fmt.Errorf("resolve package: %w", err)
	}
	info := resolved.Info
	workAPK := resolved.WorkAPK
	progress(1, totalSteps, "Resolving package", fmt.Sprintf("✓ (%s)", resolved.Bundle.Format))

	if err := os.MkdirAll(a.cfg.OutputDir, 0o750); err != nil {
		return nil, fmt.Errorf("mkdir output: %w", err)
	}
	workDir := filepath.Join(a.cfg.OutputDir, "work")
	if a.cfg.UseCache {
		store := cache.New(filepath.Join(a.cfg.OutputDir, "cache"))
		dir, err := store.Ensure(info.SHA256)
		if err != nil {
			return nil, err
		}
		workDir = dir
		_ = store.WriteMeta(info.SHA256, cache.Meta{
			SHA256:    info.SHA256,
			CreatedAt: time.Now().UTC(),
			APKPath:   a.cfg.APKPath,
		})
	} else {
		_ = os.RemoveAll(workDir)
		if err := os.MkdirAll(workDir, 0o750); err != nil {
			return nil, err
		}
	}

	// Extract native libs for JNI symbol inventory (best-effort).
	libDir := filepath.Join(workDir, "native-libs")
	_ = apk.ExtractSafe(workAPK, libDir, func(name string) bool {
		return strings.HasPrefix(name, "lib/") && strings.HasSuffix(name, ".so")
	})
	for _, split := range resolved.AllAPKs {
		if split == workAPK {
			continue
		}
		_ = apk.ExtractSafe(split, libDir, func(name string) bool {
			return strings.HasPrefix(name, "lib/") && strings.HasSuffix(name, ".so")
		})
	}

	toolReport := doctor.Check(ctx, a.cfg.Paths)
	if !toolReport.OK {
		progress(2, totalSteps, "Checking tools", "✗")
		return nil, fmt.Errorf("required tools missing — run: apkcheck doctor")
	}
	progress(2, totalSteps, "Checking tools", "✓")

	progress(3, totalSteps, "Running Apktool", "…")
	at := apktool.New(a.cfg.Paths.Apktool)
	decode, err := at.Decode(ctx, workAPK, workDir)
	if err != nil {
		progress(3, totalSteps, "Running Apktool", "✗")
		return nil, fmt.Errorf("apktool (required for Smali ground truth): %w", err)
	}
	progress(3, totalSteps, "Running Apktool", fmt.Sprintf("✓ (%d methods)", len(decode.Methods)))
	if decode.Manifest != "" {
		apk.EnrichFromManifestYAML(info, decode.Manifest)
	}

	enabled := map[string]bool{}
	for _, d := range a.cfg.Decompilers {
		enabled[strings.ToLower(d)] = true
	}

	type namedResult struct {
		name string
		res  *decompiler.Result
	}
	var decResults []namedResult
	var mu sync.Mutex

	runDec := func(name string, d decompiler.Decompiler) error {
		if !enabled[name] {
			return nil
		}
		if !d.Available(ctx) {
			a.log.Warn("decompiler unavailable, skipping", "name", name)
			mu.Lock()
			decResults = append(decResults, namedResult{name: name, res: &decompiler.Result{
				Name: name, Failed: true, FailReason: "not available",
			}})
			mu.Unlock()
			return nil
		}
		res, err := d.Decompile(ctx, decompiler.Input{
			APKPath: workAPK,
			OutDir:  workDir,
			Workers: a.cfg.Workers,
		})
		if err != nil && res == nil {
			a.log.Error("decompiler error", "name", name, "err", err)
			mu.Lock()
			decResults = append(decResults, namedResult{name: name, res: &decompiler.Result{
				Name: name, Failed: true, FailReason: err.Error(),
			}})
			mu.Unlock()
			return nil // soft-fail: never abort whole analysis for optional path
		}
		if res == nil {
			res = &decompiler.Result{Name: name, Failed: true, FailReason: "nil result"}
		}
		mu.Lock()
		decResults = append(decResults, namedResult{name: name, res: res})
		mu.Unlock()
		return nil
	}

	progress(4, totalSteps, "Running JADX", "…")
	_ = runDec("jadx", jadx.New(a.cfg.Paths.JADX))
	jadxOK := false
	for _, nr := range decResults {
		if nr.name == "jadx" && nr.res != nil && !nr.res.Failed {
			jadxOK = true
			progress(4, totalSteps, "Running JADX", fmt.Sprintf("✓ (%d methods)", len(nr.res.MethodIRs)))
			break
		}
	}
	if !jadxOK {
		progress(4, totalSteps, "Running JADX", "⚠ partial/failed")
	}

	progress(5, totalSteps, "Running optional decompilers", "…")
	g, _ := errgroup.WithContext(ctx)
	g.SetLimit(2)
	g.Go(func() error { return runDec("cfr", cfr.New(a.cfg.Paths.CFR, a.cfg.Paths.Java)) })
	g.Go(func() error {
		return runDec("fernflower", fernflower.New(a.cfg.Paths.FernFlower, a.cfg.Paths.Java))
	})
	_ = g.Wait()
	progress(5, totalSteps, "Running optional decompilers", "✓")

	progress(6, totalSteps, "Comparing methods", "…")
	indexes := map[string]map[string][]*ir.MethodIR{}
	for _, nr := range decResults {
		if nr.res == nil {
			continue
		}
		indexes[nr.name] = diff.IndexByFuzzyKey(nr.res.MethodIRs)
	}

	skippedFramework, skippedSynthetic, skippedEmpty := 0, 0, 0
	smaliMethods := make([]*ir.MethodIR, 0, len(decode.Methods))
	for _, m := range decode.Methods {
		if m == nil {
			continue
		}
		if !a.cfg.IncludeEmpty && isEmptyMethod(m) {
			skippedEmpty++
			continue
		}
		if a.cfg.SkipFramework && androidx.IsFrameworkPackage(m.ClassName) {
			skippedFramework++
			continue
		}
		if a.cfg.SkipSynthetic && androidx.IsKotlinSynthetic(m.ClassName, m.MethodName) {
			skippedSynthetic++
			continue
		}
		smaliMethods = append(smaliMethods, m)
	}

	if a.cfg.ClassFilter != "" || a.cfg.MethodFilter != "" {
		smaliMethods = filterMethods(smaliMethods, a.cfg.ClassFilter, a.cfg.MethodFilter)
	}
	if a.cfg.Limit > 0 && len(smaliMethods) > a.cfg.Limit {
		smaliMethods = prioritize(smaliMethods, a.cfg.Limit)
	}

	results := make([]model.MethodResult, len(smaliMethods))
	var done atomic.Int64
	var eg errgroup.Group
	eg.SetLimit(a.cfg.Workers)
	total := int64(len(smaliMethods))
	for i := range smaliMethods {
		i := i
		eg.Go(func() error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			sm := smaliMethods[i]
			matched := map[string]*ir.MethodIR{}
			for name, idx := range indexes {
				matched[name] = diff.Match(sm, idx)
			}
			mr := diff.CompareMethod(sm, matched)
			tags := security.Analyze(sm)
			if androidx.IsKotlinCoroutineContinuation(sm.ClassName) || sm.MethodName == "invokeSuspend" {
				tags = appendUnique(tags, "kotlin_coroutine")
			}
			for _, f := range sm.AccessFlags {
				if f == "kotlin-origin" {
					tags = appendUnique(tags, "kotlin")
				}
				if f == "native" {
					mr.NativeBridge = true
					tags = appendUnique(tags, "native")
				}
			}
			if len(tags) > 0 || security.IsExportedComponentHeuristic(sm.ClassName, sm.MethodName) {
				mr.SecurityRelevant = true
				mr.SecurityTags = tags
				if security.IsExportedComponentHeuristic(sm.ClassName, sm.MethodName) {
					mr.SecurityTags = appendUnique(mr.SecurityTags, "entrypoint")
				}
			}
			results[i] = mr
			n := done.Add(1)
			if n%500 == 0 || n == total {
				fmt.Fprintf(os.Stderr, "\r      compared %d/%d methods", n, total)
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		fmt.Fprintln(os.Stderr)
		return nil, err
	}
	if total > 0 {
		fmt.Fprintln(os.Stderr)
	}

	if a.cfg.Focus == "security" {
		filtered := results[:0]
		for _, r := range results {
			if r.SecurityRelevant {
				filtered = append(filtered, r)
			}
		}
		results = filtered
	}

	sort.Slice(results, func(i, j int) bool {
		si, sj := rankStatus(results[i].Status), rankStatus(results[j].Status)
		if si != sj {
			return si < sj
		}
		if results[i].SecurityRelevant != results[j].SecurityRelevant {
			return results[i].SecurityRelevant
		}
		return results[i].Ref.Key() < results[j].Ref.Key()
	})

	progress(6, totalSteps, "Comparing methods", fmt.Sprintf("✓ (%d compared)", len(results)))

	notes := []string{
		"Never treat a single decompiler as authoritative.",
		"Insufficient evidence is reported explicitly rather than guessed.",
		"DEX/Smali is the source of truth for every verdict.",
		"Syntactically valid ≠ behaviorally equivalent.",
	}
	if skippedFramework > 0 {
		notes = append(notes, fmt.Sprintf("Skipped %d framework/library methods (--skip-framework).", skippedFramework))
	}
	if skippedSynthetic > 0 {
		notes = append(notes, fmt.Sprintf("Skipped %d Kotlin/R8 synthetic methods (--skip-synthetic).", skippedSynthetic))
	}
	if skippedEmpty > 0 {
		notes = append(notes, fmt.Sprintf("Skipped %d empty/abstract/native methods.", skippedEmpty))
	}
	if resolved.Bundle != nil && resolved.Bundle.Format != "apk" {
		notes = append(notes, fmt.Sprintf("Logical app format=%s with %d splits.", resolved.Bundle.Format, len(resolved.Bundle.Splits)))
	}

	out := &model.AnalysisResult{
		SchemaVersion: model.SchemaVersion,
		ToolVersion:   Version,
		GeneratedAt:   time.Now().UTC(),
		APK:           *info,
		Bundle:        resolved.Bundle,
		Tools:         toolReport.Tools,
		Methods:       results,
		Focus:         a.cfg.Focus,
		Limitations: []string{
			"DEX/Smali is the source of truth; decompiler agreement is not proof of correctness.",
			"Java AST extraction is heuristic; Kotlin coroutine state machines need manual review.",
			"CFG comparison is structural; equivalent boolean rewrites may be flagged for manual review.",
			"FernFlower often requires DEX-to-JAR conversion; soft-fail when sources are absent.",
			"Signing certificate details are not fully parsed.",
		},
		Notes: notes,
	}
	out.Summary = summarize(results)
	out.Summary.SkippedFramework = skippedFramework
	out.Summary.SkippedSynthetic = skippedSynthetic
	out.Summary.SkippedEmpty = skippedEmpty
	out.Summary.SmaliMethodsTotal = len(decode.Methods)

	for _, nr := range decResults {
		if nr.res != nil && nr.res.Failed {
			out.Notes = append(out.Notes, fmt.Sprintf("%s: %s", nr.name, nr.res.FailReason))
		}
	}

	progress(7, totalSteps, "Security + evidence graph", "…")
	enrich.Apply(out, enrich.Options{
		Manifest:    decode.Manifest,
		MethodIR:    decode.Methods,
		ExtractedSO: libDir,
		Bundle:      resolved.Bundle,
	})
	progress(7, totalSteps, "Security + evidence graph", fmt.Sprintf("✓ (%d findings)", len(out.Findings)))

	return out, nil
}

func isEmptyMethod(m *ir.MethodIR) bool {
	if m == nil {
		return true
	}
	for _, f := range m.AccessFlags {
		if f == "abstract" || f == "native" {
			return true
		}
	}
	// Only trivial return / empty bodies
	real := 0
	for _, ins := range m.Instructions {
		if ins.Opcode == "" {
			continue
		}
		real++
	}
	return real == 0
}

func prioritize(methods []*ir.MethodIR, limit int) []*ir.MethodIR {
	// Prefer security-relevant and non-framework app methods.
	type scored struct {
		m *ir.MethodIR
		s int
	}
	items := make([]scored, 0, len(methods))
	for _, m := range methods {
		sc := 0
		if !androidx.IsFrameworkPackage(m.ClassName) {
			sc += 3
		}
		if security.IsExportedComponentHeuristic(m.ClassName, m.MethodName) {
			sc += 5
		}
		if len(security.Analyze(m)) > 0 {
			sc += 4
		}
		if androidx.IsKotlinSynthetic(m.ClassName, m.MethodName) {
			sc -= 2
		}
		items = append(items, scored{m: m, s: sc})
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].s != items[j].s {
			return items[i].s > items[j].s
		}
		return items[i].m.Ref() < items[j].m.Ref()
	})
	out := make([]*ir.MethodIR, 0, limit)
	for i := 0; i < len(items) && i < limit; i++ {
		out = append(out, items[i].m)
	}
	return out
}

func filterMethods(methods []*ir.MethodIR, class, method string) []*ir.MethodIR {
	class = androidx.NormalizeClassName(class)
	var out []*ir.MethodIR
	for _, m := range methods {
		cn := androidx.NormalizeClassName(m.ClassName)
		if class != "" && !strings.EqualFold(cn, class) &&
			!strings.HasSuffix(strings.ToLower(cn), "."+strings.ToLower(class)) &&
			!strings.Contains(strings.ToLower(cn), strings.ToLower(class)) {
			continue
		}
		if method != "" && m.MethodName != method {
			continue
		}
		out = append(out, m)
	}
	return out
}

func summarize(methods []model.MethodResult) model.AnalysisSummary {
	var s model.AnalysisSummary
	s.MethodsAnalyzed = len(methods)
	for _, m := range methods {
		if m.SecurityRelevant {
			s.SecurityRelevant++
		}
		switch m.Status {
		case model.ConfidenceConsistent:
			s.MethodsConsistent++
		case model.ConfidencePartiallyConsistent:
			s.MethodsPartial++
		case model.ConfidenceDisagreement:
			s.MethodsDisagreement++
		default:
			s.MethodsUnresolved++
		}
		for _, d := range m.Decompilers {
			if d.Status == model.ConfidenceToolFailure {
				s.ToolFailures++
			}
			if d.Status == model.ConfidenceParseFailure {
				s.ParseFailures++
			}
		}
	}
	return s
}

func rankStatus(c model.Confidence) int {
	switch c {
	case model.ConfidenceDisagreement:
		return 0
	case model.ConfidencePartiallyConsistent:
		return 1
	case model.ConfidenceUnresolved, model.ConfidenceInsufficientEvidence:
		return 2
	default:
		return 3
	}
}

func appendUnique(in []string, v string) []string {
	for _, x := range in {
		if x == v {
			return in
		}
	}
	return append(in, v)
}
