// Package markdown writes shareable REPORT.md hunt artifacts.
package markdown

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/armin/apkcheck/pkg/model"
)

// WriteFile writes REPORT.md from an AnalysisResult / Hunt payload.
func WriteFile(path string, r *model.AnalysisResult) error {
	if r == nil {
		return fmt.Errorf("nil analysis result")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# APKCheck Hunt Report\n\n")
	fmt.Fprintf(&b, "> **DEX/Smali is the ground truth; decompilers are reconstructions; runtime is partial observation.**\n\n")
	fmt.Fprintf(&b, "Generated: %s · apkcheck %s · schema %s\n\n",
		r.GeneratedAt.Format(time.RFC3339), r.ToolVersion, r.SchemaVersion)

	b.WriteString("## Evidence legend\n\n")
	b.WriteString("| Label | Meaning |\n|-------|--------|\n")
	b.WriteString("| `FACT` / `STATIC_EVIDENCE` | Observed in APK/DEX/Smali/manifest |\n")
	b.WriteString("| `RUNTIME_OBSERVATION` | Seen on an exercised path only |\n")
	b.WriteString("| `INFERENCE` | Heuristic conclusion — not a confirmed vulnerability |\n")
	b.WriteString("| `UNCERTAINTY` | Insufficient evidence |\n")
	b.WriteString("| `NOT OBSERVED ≠ ABSENT` | Missing runtime hit does not prove absence |\n\n")

	b.WriteString("## Application Overview\n\n")
	fmt.Fprintf(&b, "- **Path:** `%s`\n", r.APK.Path)
	fmt.Fprintf(&b, "- **SHA-256:** `%s`\n", r.APK.SHA256)
	if r.APK.Package != "" {
		fmt.Fprintf(&b, "- **Package:** `%s` %s (%d)\n", r.APK.Package, r.APK.VersionName, r.APK.VersionCode)
	}
	fmt.Fprintf(&b, "- **SDK:** min=%d target=%d\n", r.APK.MinSDK, r.APK.TargetSDK)
	fmt.Fprintf(&b, "- **DEX files:** %d\n", r.APK.DEXCount)
	if r.Bundle != nil {
		fmt.Fprintf(&b, "- **Bundle format:** `%s` (%d splits)\n", r.Bundle.Format, len(r.Bundle.Splits))
		for _, s := range r.Bundle.Splits {
			fmt.Fprintf(&b, "  - `%s` (%s) — %s\n", s.Name, s.Kind, s.Path)
		}
	}
	b.WriteString("\n")

	b.WriteString("## Manifest Analysis\n\n")
	writeList(&b, "Activities", r.APK.Activities)
	writeList(&b, "Services", r.APK.Services)
	writeList(&b, "Receivers", r.APK.Receivers)
	writeList(&b, "Providers", r.APK.Providers)
	b.WriteString("\n")

	b.WriteString("## Permissions\n\n")
	if len(r.APK.Permissions) == 0 {
		b.WriteString("_None extracted._\n\n")
	} else {
		for _, p := range r.APK.Permissions {
			fmt.Fprintf(&b, "- `%s`\n", p)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Exported Components\n\n")
	writeList(&b, "Exported Activities", r.APK.ExportedActivities)
	writeList(&b, "Exported Services", r.APK.ExportedServices)
	writeList(&b, "Exported Receivers", r.APK.ExportedReceivers)
	writeList(&b, "Exported Providers", r.APK.ExportedProviders)
	b.WriteString("\n")

	b.WriteString("## Security Findings\n\n")
	writeFindings(&b, filterCat(r.Findings, false))
	b.WriteString("## Hardcoded Secrets\n\n")
	writeFindings(&b, filterBy(r.Findings, model.CatHardcodedSecret))
	b.WriteString("## Interesting APIs\n\n")
	writeFindings(&b, filterInteresting(r.Findings))

	b.WriteString("## Decompiler Disagreements\n\n")
	n := 0
	for _, m := range r.Methods {
		if m.Status != model.ConfidenceDisagreement {
			continue
		}
		n++
		fmt.Fprintf(&b, "### `%s`\n\n", m.Ref.String())
		fmt.Fprintf(&b, "- **Status:** `%s`\n", m.Status)
		fmt.Fprintf(&b, "- **Semantic:** `SEMANTIC_CONFIDENCE: %s`\n", m.SemanticConfidence)
		fmt.Fprintf(&b, "- **Verdict:** %s\n\n", m.Verdict)
		if n >= 40 {
			b.WriteString("_…truncated_\n\n")
			break
		}
	}
	if n == 0 {
		b.WriteString("_No material disagreements in analyzed set._\n\n")
	}

	b.WriteString("## Semantic Confidence\n\n")
	b.WriteString("| Method | Syntactic | Behavioral | Confidence |\n|--------|-----------|------------|------------|\n")
	for i, s := range r.Semantic {
		if i >= 50 {
			break
		}
		fmt.Fprintf(&b, "| `%s.%s` | %v | %v | `%s` |\n",
			shortClass(s.Ref.Class), s.Ref.Name, s.SyntacticallyValid, s.BehaviorallyEquiv, s.Confidence)
	}
	if len(r.Semantic) == 0 {
		b.WriteString("| — | — | — | — |\n")
	}
	b.WriteString("\n")

	b.WriteString("## Native Libraries\n\n")
	if len(r.Native) == 0 {
		b.WriteString("_None._\n\n")
	} else {
		for _, n := range r.Native {
			fmt.Fprintf(&b, "- `%s` (%s) size=%d split=%s\n", n.Path, n.ABI, n.Size, n.Split)
			if len(n.JNISymbols) > 0 {
				fmt.Fprintf(&b, "  - JNI symbols: %s\n", strings.Join(limit(n.JNISymbols, 8), ", "))
			}
		}
		b.WriteString("\n")
	}

	b.WriteString("## JNI Relationships\n\n")
	if len(r.JNI) == 0 {
		b.WriteString("_No native methods mapped._\n\n")
	} else {
		b.WriteString("```text\nJava/Kotlin → native method → JNI → .so\n```\n\n")
		for _, j := range r.JNI {
			fmt.Fprintf(&b, "- `%s.%s` → `%s` / `%s` [%s]\n",
				j.ClassName, j.Method, j.Library, j.JNISymbol, j.EClass)
			fmt.Fprintf(&b, "  - %s\n", j.Evidence)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Runtime Observations\n\n")
	if len(r.RuntimeObs) == 0 {
		b.WriteString("_No runtime session in this hunt (static-only) or no observations recorded._\n\n")
		b.WriteString("> **NOT OBSERVED ≠ ABSENT**\n\n")
	} else {
		for _, o := range r.RuntimeObs {
			fmt.Fprintf(&b, "- [`%s`] %s — %s\n", o.Class, o.Kind, o.Message)
			if o.Note != "" {
				fmt.Fprintf(&b, "  - %s\n", o.Note)
			}
		}
		b.WriteString("\n")
	}

	b.WriteString("## Smali Evidence\n\n")
	fmt.Fprintf(&b, "- Methods analyzed: **%d** / Smali total **%d**\n",
		r.Summary.MethodsAnalyzed, r.Summary.SmaliMethodsTotal)
	fmt.Fprintf(&b, "- Consistent: %d · Partial: %d · Disagreement: %d · Unresolved: %d\n\n",
		r.Summary.MethodsConsistent, r.Summary.MethodsPartial,
		r.Summary.MethodsDisagreement, r.Summary.MethodsUnresolved)

	b.WriteString("## AI Analysis\n\n")
	b.WriteString("Use `apkcheck analyze --format ai` or `apkcheck mcp` to query the evidence graph.\n")
	b.WriteString("AI must reason over collected evidence — it is not a source of truth.\n\n")

	b.WriteString("## Recommendations\n\n")
	recs := r.Recommendations
	if len(recs) == 0 {
		recs = defaultRecs(r)
	}
	for _, rec := range recs {
		fmt.Fprintf(&b, "- %s\n", rec)
	}
	b.WriteString("\n")

	b.WriteString("## Limitations\n\n")
	for _, l := range r.Limitations {
		fmt.Fprintf(&b, "- %s\n", l)
	}
	b.WriteString("\n---\n*APKCheck — Smali-backed cross-decompiler verification + evidence discipline.*\n")

	return os.WriteFile(path, []byte(b.String()), 0o640)
}

func writeList(b *strings.Builder, title string, items []string) {
	fmt.Fprintf(b, "### %s\n\n", title)
	if len(items) == 0 {
		b.WriteString("_None._\n\n")
		return
	}
	for _, it := range items {
		fmt.Fprintf(b, "- `%s`\n", it)
	}
	b.WriteString("\n")
}

func writeFindings(b *strings.Builder, fs []model.Finding) {
	if len(fs) == 0 {
		b.WriteString("_None._\n\n")
		return
	}
	for _, f := range fs {
		fmt.Fprintf(b, "### %s — %s\n\n", f.ID, f.Title)
		fmt.Fprintf(b, "- **Severity:** `%s`\n", f.Severity)
		fmt.Fprintf(b, "- **Evidence class:** `%s`\n", f.Class)
		fmt.Fprintf(b, "- **Confidence:** `%s`\n", f.Confidence)
		fmt.Fprintf(b, "- **Summary:** %s\n", f.Summary)
		fmt.Fprintf(b, "- **Why:** %s\n", f.Why)
		if len(f.Evidence) > 0 {
			b.WriteString("- **Evidence:**\n")
			for _, e := range f.Evidence {
				fmt.Fprintf(b, "  - class=`%s` method=`%s` smali=`%s` manifest=`%s`\n",
					e.Class, e.Method, e.SmaliInsn, e.Manifest)
			}
		}
		if f.ManualCheck {
			b.WriteString("- **Manual check required**\n")
		}
		b.WriteString("\n")
	}
}

func filterBy(fs []model.Finding, cat model.FindingCategory) []model.Finding {
	var out []model.Finding
	for _, f := range fs {
		if f.Category == cat {
			out = append(out, f)
		}
	}
	return out
}

func filterCat(fs []model.Finding, _ bool) []model.Finding {
	var out []model.Finding
	for _, f := range fs {
		if f.Category == model.CatHardcodedSecret {
			continue
		}
		if f.Category == model.CatDecompilerDisagree {
			continue
		}
		out = append(out, f)
	}
	return out
}

func filterInteresting(fs []model.Finding) []model.Finding {
	var out []model.Finding
	for _, f := range fs {
		switch f.Category {
		case model.CatDangerousAPI, model.CatWebView, model.CatAuthz, model.CatInsecureStorage:
			out = append(out, f)
		}
	}
	return out
}

func shortClass(c string) string {
	if i := strings.LastIndex(c, "."); i >= 0 {
		return c[i+1:]
	}
	return c
}

func limit(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return append(in[:n], "…")
}

func defaultRecs(r *model.AnalysisResult) []string {
	var out []string
	out = append(out, "Review all `STATIC_EVIDENCE` findings with severity ≥ high before shipping.")
	out = append(out, "Treat `INFERENCE` items as triage hints — confirm against Smali before filing vulns.")
	if r.Summary.MethodsDisagreement > 0 {
		out = append(out, "Open the HTML method browser (Show Disagreements) for methods where decompilers diverge.")
	}
	if len(r.JNI) > 0 {
		out = append(out, "Native-bridged methods need .so review (Ghidra/IDA) — Java reconstructions are incomplete.")
	}
	out = append(out, "If runtime was not run: absence of RUNTIME_OBSERVATION does not mean controls are absent.")
	return out
}
