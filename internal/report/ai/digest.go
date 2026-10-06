// Package ai builds compact, agent-oriented digests from APKCheck reports.
//
// Digests are intentionally lossy: they prioritize disagreements, security
// hotspots, runtime observations, and actionable next steps for LLM consumers.
package ai

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/armin/apkcheck/pkg/model"
)

const Schema = "apkcheck.ai.v1"

// Digest is an AI-optimized summary of an analysis (static ± runtime).
type Digest struct {
	Schema        string               `json:"schema"`
	ToolVersion   string               `json:"tool_version"`
	GeneratedAt   time.Time            `json:"generated_at"`
	APK           DigestAPK            `json:"apk"`
	Principles    []string             `json:"principles"`
	Summary       DigestSummary        `json:"summary"`
	TopFindings   []Finding            `json:"top_findings"`
	Disagreements []Finding            `json:"disagreements"`
	Security      []Finding            `json:"security_hotspots"`
	Unresolved    []Finding            `json:"unresolved,omitempty"`
	Runtime       *model.RuntimeReport `json:"runtime,omitempty"`
	Tools         []model.ToolStatus   `json:"tools,omitempty"`
	Limitations   []string             `json:"limitations"`
	NextActions   []string             `json:"next_actions"`
	Notes         []string             `json:"notes,omitempty"`
}

type DigestAPK struct {
	Path        string `json:"path"`
	SHA256      string `json:"sha256,omitempty"`
	Package     string `json:"package,omitempty"`
	VersionName string `json:"version_name,omitempty"`
	MinSDK      int    `json:"min_sdk,omitempty"`
	TargetSDK   int    `json:"target_sdk,omitempty"`
	DEXCount    int    `json:"dex_count,omitempty"`
}

type DigestSummary struct {
	MethodsAnalyzed  int `json:"methods_analyzed"`
	Consistent       int `json:"consistent"`
	Partial          int `json:"partial"`
	Disagreement     int `json:"disagreement"`
	Unresolved       int `json:"unresolved"`
	SecurityRelevant int `json:"security_relevant"`
}

// Finding is one compact method-level signal for agents.
type Finding struct {
	Method   string   `json:"method"`
	Status   string   `json:"status"`
	Verdict  string   `json:"verdict,omitempty"`
	Severity string   `json:"severity,omitempty"` // high|medium|low|info
	Tags     []string `json:"tags,omitempty"`
	Issues   []string `json:"issues,omitempty"`
	Evidence string   `json:"evidence_class,omitempty"` // STATIC|RUNTIME|INFERENCE|UNRESOLVED
}

type scored struct {
	f Finding
	w int
}

// Options controls digest size.
type Options struct {
	MaxFindings      int
	MaxDisagreements int
	MaxSecurity      int
	MaxUnresolved    int
}

func defaultOpts(o Options) Options {
	if o.MaxFindings <= 0 {
		o.MaxFindings = 25
	}
	if o.MaxDisagreements <= 0 {
		o.MaxDisagreements = 40
	}
	if o.MaxSecurity <= 0 {
		o.MaxSecurity = 40
	}
	if o.MaxUnresolved <= 0 {
		o.MaxUnresolved = 20
	}
	return o
}

// FromResult builds a Digest from a full AnalysisResult.
func FromResult(r *model.AnalysisResult, opt Options) *Digest {
	if r == nil {
		return &Digest{
			Schema:      Schema,
			GeneratedAt: time.Now().UTC(),
			Principles:  principles(),
			Limitations: []string{"no analysis result provided"},
			NextActions: []string{"run: apkcheck analyze <apk> --format ai"},
		}
	}
	opt = defaultOpts(opt)
	d := &Digest{
		Schema:      Schema,
		ToolVersion: r.ToolVersion,
		GeneratedAt: r.GeneratedAt,
		APK: DigestAPK{
			Path: r.APK.Path, SHA256: r.APK.SHA256, Package: r.APK.Package,
			VersionName: r.APK.VersionName, MinSDK: r.APK.MinSDK, TargetSDK: r.APK.TargetSDK,
			DEXCount: r.APK.DEXCount,
		},
		Principles: principles(),
		Summary: DigestSummary{
			MethodsAnalyzed:  r.Summary.MethodsAnalyzed,
			Consistent:       r.Summary.MethodsConsistent,
			Partial:          r.Summary.MethodsPartial,
			Disagreement:     r.Summary.MethodsDisagreement,
			Unresolved:       r.Summary.MethodsUnresolved,
			SecurityRelevant: r.Summary.SecurityRelevant,
		},
		Runtime:     r.Runtime,
		Tools:       r.Tools,
		Limitations: append([]string{}, r.Limitations...),
		Notes:       append([]string{}, r.Notes...),
	}
	if len(d.Limitations) == 0 {
		d.Limitations = append(d.Limitations,
			"DEX/Smali is the source of truth; decompiler agreement is not proof of correctness",
			"NOT OBSERVED ≠ absent — runtime covers exercised paths only",
		)
	}

	var disagrees, secs, unresolved, top []scored

	for _, m := range r.Methods {
		f := findingFromMethod(m)
		switch m.Status {
		case model.ConfidenceDisagreement:
			disagrees = append(disagrees, scored{f, 100 + severityWeight(f.Severity)})
			top = append(top, scored{f, 90 + severityWeight(f.Severity)})
		case model.ConfidencePartiallyConsistent:
			disagrees = append(disagrees, scored{f, 60 + severityWeight(f.Severity)})
			top = append(top, scored{f, 50 + severityWeight(f.Severity)})
		case model.ConfidenceUnresolved:
			unresolved = append(unresolved, scored{f, 40})
		}
		if m.SecurityRelevant {
			sf := f
			if sf.Severity == "" {
				sf.Severity = "medium"
			}
			secs = append(secs, scored{sf, 70 + severityWeight(sf.Severity)})
			top = append(top, scored{sf, 70 + severityWeight(sf.Severity)})
		}
	}

	d.Disagreements = takeScored(disagrees, opt.MaxDisagreements)
	d.Security = takeScored(secs, opt.MaxSecurity)
	d.Unresolved = takeScored(unresolved, opt.MaxUnresolved)
	d.TopFindings = takeScored(top, opt.MaxFindings)
	d.NextActions = nextActions(d)
	return d
}

func principles() []string {
	return []string{
		"DEX/Smali is the source of truth",
		"Decompilers are reconstructions, not oracles",
		"Runtime observations cover exercised paths only",
		"NOT OBSERVED does not mean the behavior is absent",
		"Do not invent vulnerability confirmations from disagreement alone",
	}
}

func findingFromMethod(m model.MethodResult) Finding {
	f := Finding{
		Method:  m.Ref.String(),
		Status:  string(m.Status),
		Verdict: m.Verdict,
		Tags:    append([]string{}, m.SecurityTags...),
	}
	switch m.Status {
	case model.ConfidenceDisagreement:
		f.Evidence = "STATIC"
		f.Severity = "high"
	case model.ConfidencePartiallyConsistent:
		f.Evidence = "STATIC"
		f.Severity = "medium"
	case model.ConfidenceUnresolved:
		f.Evidence = "UNRESOLVED"
		f.Severity = "low"
	default:
		f.Evidence = "STATIC"
		f.Severity = "info"
	}
	if m.SecurityRelevant && f.Severity == "info" {
		f.Severity = "medium"
	}
	for _, iss := range m.Issues {
		line := iss.Message
		if iss.Type != "" {
			line = fmt.Sprintf("[%s] %s", iss.Type, iss.Message)
		}
		f.Issues = append(f.Issues, line)
		if len(f.Issues) >= 5 {
			break
		}
	}
	return f
}

func severityWeight(s string) int {
	switch strings.ToLower(s) {
	case "high":
		return 30
	case "medium":
		return 15
	case "low":
		return 5
	default:
		return 0
	}
}

func takeScored(in []scored, n int) []Finding {
	sort.Slice(in, func(i, j int) bool {
		if in[i].w != in[j].w {
			return in[i].w > in[j].w
		}
		return in[i].f.Method < in[j].f.Method
	})
	seen := map[string]bool{}
	out := make([]Finding, 0, n)
	for _, s := range in {
		if seen[s.f.Method] {
			continue
		}
		seen[s.f.Method] = true
		out = append(out, s.f)
		if len(out) >= n {
			break
		}
	}
	return out
}

func nextActions(d *Digest) []string {
	var a []string
	if d.Summary.Disagreement > 0 {
		a = append(a, "Inspect disagreements against Smali (source of truth), not against other decompilers")
	}
	if d.Summary.SecurityRelevant > 0 {
		a = append(a, "Review security_hotspots with --focus security and method deep-dives")
	}
	if d.Runtime == nil {
		a = append(a, "Optional runtime: apkcheck emulator-create && apkcheck runtime <apk> --emulator <AVD>")
		a = append(a, "Or physical: apkcheck devices && apkcheck runtime <apk> --device")
	} else if d.Runtime.Crashes > 0 {
		a = append(a, "Investigate runtime crashes in session logcat / timeline")
	}
	if d.Summary.Unresolved > 0 {
		a = append(a, "Unresolved methods often mean soft-failed decompilers — check apkcheck doctor")
	}
	a = append(a, "Use MCP tools (apkcheck mcp) or --format ai for agent-consumable digests")
	return a
}
