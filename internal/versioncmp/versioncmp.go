// Package versioncmp detects reconstruction differences across decompiler versions.
//
// A difference is reported as a VERSION DIFFERENCE — never as automatic proof
// that a newer version is "buggy".
package versioncmp

import (
	"fmt"
	"sort"
	"strings"

	"github.com/armin/apkcheck/internal/diff"
	"github.com/armin/apkcheck/internal/ir"
	"github.com/armin/apkcheck/pkg/model"
)

// MethodVersionView is one method compared across versions of tools.
type MethodVersionView struct {
	Ref      model.MethodRef            `json:"ref"`
	Smali    *model.SmaliSummary        `json:"smali,omitempty"`
	ByTool   map[string][]VersionStatus `json:"by_tool"`
	Findings []VersionFinding           `json:"findings,omitempty"`
	Verdict  string                     `json:"verdict"`
}

// VersionStatus is one pinned version's comparison against DEX.
type VersionStatus struct {
	Tool    string           `json:"tool"`
	Version string           `json:"version"`
	Key     string           `json:"key"`
	Status  model.Confidence `json:"status"`
	Issues  []model.Issue    `json:"issues,omitempty"`
}

// VersionFinding highlights cross-version divergence.
type VersionFinding struct {
	Tool     string `json:"tool"`
	Type     string `json:"type"` // version_difference | version_regression_candidate
	Message  string `json:"message"`
	Evidence string `json:"evidence,omitempty"`
}

// Report is the output of compare-versions.
type Report struct {
	Methods []MethodVersionView `json:"methods"`
	Summary struct {
		MethodsCompared      int `json:"methods_compared"`
		VersionDifferences   int `json:"version_differences"`
		RegressionCandidates int `json:"regression_candidates"`
	} `json:"summary"`
	Notes []string `json:"notes"`
}

// Compare builds a cross-version report.
// smaliMethods: ground truth
// byKey: map of "jadx@1.5.6" -> method index
func Compare(smaliMethods []*ir.MethodIR, byKey map[string]map[string][]*ir.MethodIR) *Report {
	rep := &Report{
		Notes: []string{
			"DEX/Smali is the source of truth.",
			"A version difference means reconstructions diverge — not that a version is proven buggy.",
			"Inspect DEX evidence before concluding a regression.",
		},
	}

	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, sm := range smaliMethods {
		view := MethodVersionView{
			Ref: model.MethodRef{
				Class: sm.ClassName, Name: sm.MethodName, Descriptor: sm.Descriptor,
			},
			ByTool: map[string][]VersionStatus{},
		}
		sum := sm.Summary()
		view.Smali = &model.SmaliSummary{
			Instructions: sum.Instructions, BasicBlocks: sum.BasicBlocks,
			Branches: sum.Branches, Calls: sum.Calls, Exceptions: sum.Exceptions,
			Returns: sum.Returns, FieldAccesses: sum.FieldAccesses,
		}

		perTool := map[string][]VersionStatus{}
		for _, key := range keys {
			tool, ver := splitKey(key)
			matched := diff.Match(sm, byKey[key])
			mr := diff.CompareMethod(sm, map[string]*ir.MethodIR{key: matched})
			st := VersionStatus{
				Tool: tool, Version: ver, Key: key,
				Status: mr.Decompilers[key].Status,
				Issues: mr.Decompilers[key].Issues,
			}
			if st.Status == "" {
				st.Status = model.ConfidenceUnresolved
			}
			perTool[tool] = append(perTool[tool], st)
		}
		view.ByTool = perTool
		view.Findings = detectFindings(perTool)
		view.Verdict = verdict(view)
		if len(view.Findings) > 0 {
			for _, f := range view.Findings {
				if f.Type == "version_difference" || f.Type == "version_regression_candidate" {
					rep.Summary.VersionDifferences++
				}
				if f.Type == "version_regression_candidate" {
					rep.Summary.RegressionCandidates++
				}
			}
		}
		rep.Methods = append(rep.Methods, view)
	}
	rep.Summary.MethodsCompared = len(rep.Methods)
	return rep
}

func detectFindings(perTool map[string][]VersionStatus) []VersionFinding {
	var out []VersionFinding
	for tool, versions := range perTool {
		if len(versions) < 2 {
			continue
		}
		// Sort by version id for stable messaging.
		sort.Slice(versions, func(i, j int) bool { return versions[i].Version < versions[j].Version })
		base := versions[0]
		for i := 1; i < len(versions); i++ {
			cur := versions[i]
			if cur.Status == base.Status {
				continue
			}
			ftype := "version_difference"
			// Candidate "regression": earlier more consistent than later.
			if rank(base.Status) < rank(cur.Status) {
				ftype = "version_regression_candidate"
			}
			out = append(out, VersionFinding{
				Tool:    tool,
				Type:    ftype,
				Message: fmt.Sprintf("%s reconstruction differs between versions %s and %s", tool, base.Version, cur.Version),
				Evidence: fmt.Sprintf("%s=%s → %s=%s. The reconstruction differs between versions. The DEX evidence should be inspected.",
					base.Version, base.Status, cur.Version, cur.Status),
			})
		}
	}
	return out
}

func rank(c model.Confidence) int {
	switch c {
	case model.ConfidenceConsistent:
		return 0
	case model.ConfidencePartiallyConsistent:
		return 1
	case model.ConfidenceDisagreement:
		return 2
	default:
		return 3
	}
}

func verdict(v MethodVersionView) string {
	if len(v.Findings) == 0 {
		return "No cross-version reconstruction differences detected for this method in the enabled matrix."
	}
	return "VERSION DIFFERENCE DETECTED. The reconstruction differs between versions. The DEX evidence should be inspected. This is not automatic proof of a decompiler bug."
}

func splitKey(key string) (tool, version string) {
	i := strings.LastIndex(key, "@")
	if i < 0 {
		return key, ""
	}
	return key[:i], key[i+1:]
}

// FormatText renders a human-readable version comparison.
func FormatText(rep *Report, limit int) string {
	var b strings.Builder
	b.WriteString("APKCheck Version Comparison\n\n")
	b.WriteString(fmt.Sprintf("Methods compared: %d\n", rep.Summary.MethodsCompared))
	b.WriteString(fmt.Sprintf("Version differences: %d\n", rep.Summary.VersionDifferences))
	b.WriteString(fmt.Sprintf("Regression candidates: %d\n\n", rep.Summary.RegressionCandidates))

	n := 0
	shownWithFindings := 0
	for _, m := range rep.Methods {
		if len(m.Findings) > 0 {
			if limit > 0 && shownWithFindings >= limit {
				continue
			}
			shownWithFindings++
			n++
			writeMethod(&b, m)
			continue
		}
	}
	if shownWithFindings == 0 {
		b.WriteString("No cross-version reconstruction differences in the compared set.\n")
		b.WriteString("Showing up to 5 sample methods for context:\n\n")
		for _, m := range rep.Methods {
			if n >= 5 {
				break
			}
			n++
			writeMethod(&b, m)
		}
	}
	for _, note := range rep.Notes {
		b.WriteString("• " + note + "\n")
	}
	return b.String()
}

func writeMethod(b *strings.Builder, m MethodVersionView) {
	b.WriteString("Method:\n    ")
	b.WriteString(m.Ref.Class + "." + m.Ref.Name + "()\n\n")
	tools := make([]string, 0, len(m.ByTool))
	for t := range m.ByTool {
		tools = append(tools, t)
	}
	sort.Strings(tools)
	for _, t := range tools {
		b.WriteString(strings.ToUpper(t) + "\n")
		vers := append([]VersionStatus(nil), m.ByTool[t]...)
		sort.Slice(vers, func(i, j int) bool { return vers[i].Version < vers[j].Version })
		for _, v := range vers {
			b.WriteString(fmt.Sprintf("    %-12s %s %s\n", v.Version, mark(v.Status), v.Status))
		}
		b.WriteString("\n")
	}
	b.WriteString("DEX/Smali\n    source of truth\n\n")
	for _, f := range m.Findings {
		b.WriteString("⚠ " + f.Message + "\n")
		b.WriteString("  " + f.Evidence + "\n\n")
	}
	b.WriteString(m.Verdict + "\n")
	b.WriteString(strings.Repeat("─", 48) + "\n\n")
}

func mark(c model.Confidence) string {
	switch c {
	case model.ConfidenceConsistent:
		return "✓"
	case model.ConfidencePartiallyConsistent:
		return "⚠"
	case model.ConfidenceDisagreement:
		return "✗"
	default:
		return "?"
	}
}
