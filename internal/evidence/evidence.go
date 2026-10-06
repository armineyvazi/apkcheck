// Package evidence merges static, version-matrix, and runtime findings into one
// model that carefully labels STATIC / RUNTIME / INFERENCE / UNRESOLVED.
package evidence

import (
	"fmt"
	"strings"
	"time"

	"github.com/armin/apkcheck/internal/registry"
	appruntime "github.com/armin/apkcheck/internal/runtime"
	"github.com/armin/apkcheck/internal/runtime/correlation"
	"github.com/armin/apkcheck/internal/versioncmp"
	"github.com/armin/apkcheck/pkg/model"
)

// Class labels the epistemic status of a claim.
type Class string

const (
	ClassStatic     Class = "STATIC_EVIDENCE"
	ClassRuntime    Class = "RUNTIME_OBSERVATION"
	ClassInference  Class = "INFERENCE"
	ClassUnresolved Class = "UNRESOLVED"
)

// RuntimeHit is a method-scoped runtime observation (never complete coverage).
type RuntimeHit struct {
	Kind    string `json:"kind"`
	Class   string `json:"class,omitempty"`
	Method  string `json:"method,omitempty"`
	Message string `json:"message"`
	Status  string `json:"status,omitempty"`
}

// MethodEvidence is the combined view for one method.
type MethodEvidence struct {
	Ref          model.MethodRef               `json:"ref"`
	Static       *model.MethodResult           `json:"static,omitempty"`
	VersionView  *versioncmp.MethodVersionView `json:"versions,omitempty"`
	RuntimeHits  []RuntimeHit                  `json:"runtime_hits,omitempty"`
	CoverageNote string                        `json:"coverage_note,omitempty"`
	Conclusion   string                        `json:"conclusion"`
	ClassesUsed  []Class                       `json:"evidence_classes"`
}

// Report is the final combined evidence document.
type Report struct {
	GeneratedAt    time.Time               `json:"generated_at"`
	APK            model.APKInfo           `json:"apk"`
	ToolPins       []registry.ToolIdentity `json:"tool_pins,omitempty"`
	StaticSummary  model.AnalysisSummary   `json:"static_summary"`
	VersionSummary versioncmp.Report       `json:"version_summary,omitempty"`
	Runtime        *appruntime.Evidence    `json:"runtime,omitempty"`
	Methods        []MethodEvidence        `json:"methods"`
	Notes          []string                `json:"notes"`
}

// Merge builds a combined evidence report.
func Merge(
	static *model.AnalysisResult,
	versions *versioncmp.Report,
	rt *appruntime.Evidence,
	pins []registry.ToolIdentity,
	limit int,
) *Report {
	rep := &Report{
		GeneratedAt: time.Now().UTC(),
		Notes: []string{
			"DEX/Smali answers what the program contains.",
			"Decompilers answer how versions reconstruct that content.",
			"Runtime answers what was observed on one exercised path.",
			"Never equate runtime coverage with complete program behavior.",
			"Never output simplistic correctness percentages.",
			"NOT OBSERVED ≠ behavior does not exist.",
		},
	}
	if static != nil {
		rep.APK = static.APK
		rep.StaticSummary = static.Summary
	}
	if versions != nil {
		rep.VersionSummary = *versions
	}
	rep.Runtime = rt
	rep.ToolPins = pins

	versionByKey := map[string]*versioncmp.MethodVersionView{}
	if versions != nil {
		for i := range versions.Methods {
			m := &versions.Methods[i]
			versionByKey[m.Ref.Class+"->"+m.Ref.Name] = m
		}
	}

	hits := runtimeHitsFrom(rt)

	if static != nil {
		for i, m := range static.Methods {
			if limit > 0 && i >= limit {
				break
			}
			me := MethodEvidence{
				Ref:         m.Ref,
				Static:      &static.Methods[i],
				ClassesUsed: []Class{ClassStatic},
			}
			if vv := versionByKey[m.Ref.Class+"->"+m.Ref.Name]; vv != nil {
				me.VersionView = vv
			}
			if rt != nil {
				me.RuntimeHits = matchRuntime(m.Ref, hits)
				if len(me.RuntimeHits) > 0 {
					me.ClassesUsed = append(me.ClassesUsed, ClassRuntime)
				}
				if m.Smali != nil && m.Smali.Branches > 0 {
					me.CoverageNote = fmt.Sprintf(
						"%d runtime method-hints observed in session; static method has %d branches — unobserved branches are not disproven.",
						len(me.RuntimeHits), m.Smali.Branches)
					me.ClassesUsed = append(me.ClassesUsed, ClassInference)
				}
			}
			me.Conclusion = conclude(me)
			if me.Conclusion == "" {
				me.ClassesUsed = append(me.ClassesUsed, ClassUnresolved)
			}
			rep.Methods = append(rep.Methods, me)
		}
	}
	return rep
}

func runtimeHitsFrom(rt *appruntime.Evidence) []RuntimeHit {
	if rt == nil {
		return nil
	}
	var hits []RuntimeHit
	for _, c := range rt.Crashes {
		hits = append(hits, RuntimeHit{
			Kind: "crash:" + c.Kind, Class: c.Class, Method: c.Method,
			Message: c.Summary, Status: "RUNTIME_OBSERVED",
		})
		for _, fr := range c.Frames {
			hits = append(hits, RuntimeHit{
				Kind: "stack_frame", Class: fr.Class, Method: fr.Method,
				Message: fr.Raw, Status: "RUNTIME_OBSERVED",
			})
		}
	}
	for _, link := range rt.Correlations {
		hits = append(hits, hitFromLink(link))
	}
	return hits
}

func hitFromLink(link correlation.MethodLink) RuntimeHit {
	return RuntimeHit{
		Kind: "correlation", Class: link.RuntimeClass, Method: link.RuntimeMethod,
		Message: link.Note, Status: link.Status,
	}
}

func matchRuntime(ref model.MethodRef, obs []RuntimeHit) []RuntimeHit {
	var out []RuntimeHit
	for _, o := range obs {
		if o.Method == "" {
			continue
		}
		if o.Method == ref.Name {
			if o.Class == "" || strings.EqualFold(o.Class, ref.Class) || strings.HasSuffix(o.Class, "."+lastSeg(ref.Class)) {
				out = append(out, o)
			}
		}
	}
	return out
}

func lastSeg(c string) string {
	if i := strings.LastIndex(c, "."); i >= 0 {
		return c[i+1:]
	}
	return c
}

func conclude(me MethodEvidence) string {
	var parts []string
	if me.Static != nil {
		parts = append(parts, "Static status: "+string(me.Static.Status)+". "+me.Static.Verdict)
	}
	if me.VersionView != nil && len(me.VersionView.Findings) > 0 {
		parts = append(parts, me.VersionView.Verdict)
	}
	if len(me.RuntimeHits) > 0 {
		parts = append(parts, fmt.Sprintf("Runtime: method-related observations=%d (exercised path only).", len(me.RuntimeHits)))
	} else if me.RuntimeHits != nil {
		parts = append(parts, "Runtime: no observation of this method in the session (UNRESOLVED for dynamic behavior).")
	}
	if me.CoverageNote != "" {
		parts = append(parts, me.CoverageNote)
	}
	return strings.Join(parts, "\n")
}

// FormatText renders a concise combined report.
func FormatText(rep *Report, limit int) string {
	var b strings.Builder
	b.WriteString("APKCheck Combined Evidence Report\n\n")
	b.WriteString(fmt.Sprintf("APK: %s\nSHA-256: %s\n\n", rep.APK.Path, rep.APK.SHA256))
	b.WriteString("Evidence classes used: STATIC_EVIDENCE, RUNTIME_OBSERVATION, INFERENCE, UNRESOLVED\n\n")
	n := 0
	for _, m := range rep.Methods {
		if limit > 0 && n >= limit {
			break
		}
		interesting := (m.Static != nil && m.Static.Status != model.ConfidenceConsistent) ||
			(m.VersionView != nil && len(m.VersionView.Findings) > 0) ||
			len(m.RuntimeHits) > 0
		if limit > 0 && !interesting {
			continue
		}
		n++
		b.WriteString("Method:\n    " + m.Ref.Class + "." + m.Ref.Name + "()\n\n")
		if m.Static != nil && m.Static.Smali != nil {
			s := m.Static.Smali
			b.WriteString(fmt.Sprintf("DEX:\n    %d basic blocks, %d branches, %d calls, %d exceptions\n\n",
				s.BasicBlocks, s.Branches, s.Calls, s.Exceptions))
		}
		if m.VersionView != nil {
			b.WriteString("Decompiler Versions:\n")
			for tool, vers := range m.VersionView.ByTool {
				b.WriteString("  " + strings.ToUpper(tool) + "\n")
				for _, v := range vers {
					b.WriteString(fmt.Sprintf("    %s  %s\n", v.Version, v.Status))
				}
			}
			b.WriteString("\n")
		}
		if len(m.RuntimeHits) > 0 {
			b.WriteString("Runtime:\n")
			for _, h := range m.RuntimeHits {
				b.WriteString("    " + h.Kind + ": " + h.Message + "\n")
			}
			b.WriteString("\n")
		}
		b.WriteString("Conclusion:\n" + indent(m.Conclusion) + "\n")
		b.WriteString(strings.Repeat("─", 48) + "\n\n")
	}
	for _, n := range rep.Notes {
		b.WriteString("• " + n + "\n")
	}
	return b.String()
}

func indent(s string) string {
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = "    " + lines[i]
	}
	return strings.Join(lines, "\n")
}
