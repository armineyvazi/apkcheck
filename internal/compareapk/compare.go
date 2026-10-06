// Package compareapk diffs security findings and decompiler summaries between two APK builds.
// Use this to see whether a newer app version fixed manifest/DEX issues — distinct from
// compare-versions (which diffs decompiler tool versions on one APK).
package compareapk

import (
	"fmt"
	"sort"
	"strings"

	"github.com/armin/apkcheck/pkg/model"
)

// ReleaseDiff compares two analysis results (typically two app versions).
type ReleaseDiff struct {
	OldPath      string                `json:"old_path"`
	NewPath      string                `json:"new_path"`
	OldPackage   string                `json:"old_package,omitempty"`
	NewPackage   string                `json:"new_package,omitempty"`
	OldVersion   string                `json:"old_version,omitempty"`
	NewVersion   string                `json:"new_version,omitempty"`
	Fixed        []model.Finding       `json:"likely_fixed_in_new,omitempty"`
	NewIssues    []model.Finding       `json:"new_in_new_build,omitempty"`
	Unchanged    []model.Finding       `json:"unchanged_high_static,omitempty"`
	DecompileOld model.AnalysisSummary `json:"old_decompile_summary"`
	DecompileNew model.AnalysisSummary `json:"new_decompile_summary"`
	Notes        []string              `json:"notes"`
}

// Compare findings keyed by category+title (stable enough for release triage).
func Compare(oldR, newR *model.AnalysisResult) *ReleaseDiff {
	out := &ReleaseDiff{
		Notes: []string{
			"Likely fixed = STATIC_EVIDENCE finding in old absent in new (same category+title key).",
			"New in build = STATIC_EVIDENCE in new not in old.",
			"Decompiler disagreement counts are not security fixes — verify in Smali.",
			"INFERENCE findings are excluded from fixed/new lists.",
		},
	}
	if oldR != nil {
		out.OldPath = oldR.APK.Path
		out.OldPackage = oldR.APK.Package
		out.OldVersion = oldR.APK.VersionName
		out.DecompileOld = oldR.Summary
	}
	if newR != nil {
		out.NewPath = newR.APK.Path
		out.NewPackage = newR.APK.Package
		out.NewVersion = newR.APK.VersionName
		out.DecompileNew = newR.Summary
	}
	oldStatic := indexStatic(oldR)
	newStatic := indexStatic(newR)

	for k, f := range oldStatic {
		if _, ok := newStatic[k]; !ok {
			out.Fixed = append(out.Fixed, f)
		}
	}
	for k, f := range newStatic {
		if _, ok := oldStatic[k]; !ok {
			out.NewIssues = append(out.NewIssues, f)
		} else if f.Severity == model.SeverityHigh || f.Severity == model.SeverityCritical {
			out.Unchanged = append(out.Unchanged, f)
		}
	}
	sortFindings(out.Fixed)
	sortFindings(out.NewIssues)
	sortFindings(out.Unchanged)
	return out
}

func indexStatic(r *model.AnalysisResult) map[string]model.Finding {
	m := map[string]model.Finding{}
	if r == nil {
		return m
	}
	for _, f := range r.Findings {
		if f.Class != model.EvidenceStatic && f.Class != model.EvidenceFact {
			continue
		}
		if f.Category == model.CatDecompilerDisagree {
			continue
		}
		m[key(f)] = f
	}
	return m
}

func key(f model.Finding) string {
	return string(f.Category) + "|" + strings.ToLower(f.Title)
}

func sortFindings(in []model.Finding) {
	sort.Slice(in, func(i, j int) bool { return in[i].ID < in[j].ID })
}

// FormatText renders a human-readable release diff.
func FormatText(d *ReleaseDiff) string {
	if d == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "APKCheck release diff\n  old: %s (%s %s)\n  new: %s (%s %s)\n\n",
		d.OldPath, d.OldPackage, d.OldVersion, d.NewPath, d.NewPackage, d.NewVersion)
	fmt.Fprintf(&b, "Decompiler disagreements: old=%d new=%d\n",
		d.DecompileOld.MethodsDisagreement, d.DecompileNew.MethodsDisagreement)
	fmt.Fprintf(&b, "(Disagreement delta alone does not mean a security fix.)\n\n")

	b.WriteString("Likely fixed in new build (STATIC_EVIDENCE removed):\n")
	if len(d.Fixed) == 0 {
		b.WriteString("  (none)\n")
	} else {
		for _, f := range d.Fixed {
			fmt.Fprintf(&b, "  - [%s] %s\n", f.Severity, f.Title)
		}
	}
	b.WriteString("\nNew STATIC_EVIDENCE in new build:\n")
	if len(d.NewIssues) == 0 {
		b.WriteString("  (none)\n")
	} else {
		for _, f := range d.NewIssues {
			fmt.Fprintf(&b, "  - [%s] %s\n", f.Severity, f.Title)
		}
	}
	return b.String()
}
