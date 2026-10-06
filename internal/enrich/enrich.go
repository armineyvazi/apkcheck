// Package enrich attaches findings, semantic confidence, native/JNI, and evidence graph
// onto an AnalysisResult after the core Smali/decompiler comparison.
package enrich

import (
	"path/filepath"

	"github.com/armin/apkcheck/internal/findings"
	"github.com/armin/apkcheck/internal/graph"
	"github.com/armin/apkcheck/internal/ir"
	"github.com/armin/apkcheck/internal/nativejni"
	"github.com/armin/apkcheck/internal/semantic"
	"github.com/armin/apkcheck/pkg/model"
)

// Options controls post-analysis enrichment.
type Options struct {
	Manifest    string
	MethodIR    []*ir.MethodIR // full Smali IR (for secrets / JNI), not only compared set
	ExtractedSO string         // directory containing lib/**/*.so if extracted
	Bundle      *model.BundleInfo
}

// Apply mutates result in place.
func Apply(result *model.AnalysisResult, opt Options) {
	if result == nil {
		return
	}
	if opt.Bundle != nil {
		result.Bundle = opt.Bundle
	}

	// Mark native bridges on compared methods
	nativeKeys := map[string]bool{}
	for _, m := range opt.MethodIR {
		if m == nil {
			continue
		}
		for _, f := range m.AccessFlags {
			if f == "native" {
				nativeKeys[m.ClassName+"->"+m.MethodName] = true
				break
			}
		}
	}
	for i := range result.Methods {
		key := result.Methods[i].Ref.Class + "->" + result.Methods[i].Ref.Name
		if nativeKeys[key] {
			result.Methods[i].NativeBridge = true
		}
	}

	result.Methods = semantic.Annotate(result.Methods)
	result.Semantic = semantic.AssessAll(result.Methods)

	result.Native = nativejni.Inventory(result.APK, opt.ExtractedSO)
	result.JNI = nativejni.MapJNI(opt.MethodIR, result.Native)

	result.Findings = findings.Scan(findings.Input{
		APK:      result.APK,
		Manifest: opt.Manifest,
		Methods:  result.Methods,
		MethodIR: opt.MethodIR,
	})

	result.Graph = graph.Build(result)
	result.Recommendations = recommendations(result)

	result.Limitations = append(result.Limitations,
		"Syntactically valid reconstruction ≠ behaviorally equivalent reconstruction.",
		"Security findings distinguish STATIC_EVIDENCE from INFERENCE — never treat inferences as confirmed vulns.",
		"Runtime observations (if any) are partial; NOT OBSERVED ≠ ABSENT.",
	)
	result.Notes = append(result.Notes,
		"Evidence graph links findings → class/method/Smali/manifest.",
		"AI/MCP must query evidence; AI is not a source of truth.",
	)
	_ = filepath.Separator
}

func recommendations(r *model.AnalysisResult) []string {
	var out []string
	out = append(out, "Start with STATIC_EVIDENCE findings at severity ≥ high.")
	out = append(out, "Use HTML Show Disagreements filter for decompiler trust issues.")
	highSecrets := 0
	for _, f := range r.Findings {
		if f.Category == model.CatHardcodedSecret && (f.Severity == model.SeverityHigh || f.Severity == model.SeverityCritical) {
			highSecrets++
		}
	}
	if highSecrets > 0 {
		out = append(out, "Rotate any confirmed hardcoded secrets; pattern matches require manual validation.")
	}
	if len(r.APK.ExportedProviders) > 0 || len(r.APK.ExportedServices) > 0 {
		out = append(out, "Review exported Services/Providers for unauthenticated IPC.")
	}
	if len(r.JNI) > 0 {
		out = append(out, "Follow JNI mappings into .so with a native RE tool when auth/crypto crosses the boundary.")
	}
	return out
}
