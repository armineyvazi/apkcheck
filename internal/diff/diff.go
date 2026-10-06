// Package diff performs evidence-based semantic comparison of MethodIRs.
//
// Smali/DEX is the source of truth. Decompiler reconstructions are scored
// for compatibility with that truth — never declared "correct" in absolute terms.
package diff

import (
	"fmt"
	"strings"

	"github.com/armin/apkcheck/internal/cfg"
	"github.com/armin/apkcheck/internal/ir"
	"github.com/armin/apkcheck/pkg/model"
)

// CompareMethod compares decompiler reconstructions against Smali ground truth.
func CompareMethod(smali *ir.MethodIR, decompilers map[string]*ir.MethodIR) model.MethodResult {
	ref := model.MethodRef{
		Class:      smali.ClassName,
		Name:       smali.MethodName,
		Descriptor: smali.Descriptor,
		ReturnType: string(smali.ReturnType),
	}
	for _, p := range smali.Parameters {
		ref.Parameters = append(ref.Parameters, string(p))
	}

	sum := smali.Summary()
	result := model.MethodResult{
		Ref: ref,
		Smali: &model.SmaliSummary{
			Instructions:  sum.Instructions,
			BasicBlocks:   sum.BasicBlocks,
			Branches:      sum.Branches,
			Calls:         sum.Calls,
			FieldAccesses: sum.FieldAccesses,
			Returns:       sum.Returns,
			Throws:        sum.Throws,
			Exceptions:    sum.Exceptions,
			Monitors:      sum.Monitors,
			ObjectCreates: sum.ObjectCreates,
			Constants:     sum.Constants,
		},
		Decompilers: map[string]model.DecompilerMethodResult{},
	}

	if sum.Instructions == 0 {
		result.Status = model.ConfidenceInsufficientEvidence
		result.Verdict = "Insufficient bytecode evidence to validate reconstructions."
		result.Issues = append(result.Issues, model.Issue{
			Type:        model.IssueInsufficientEvidence,
			Severity:    model.SeverityLow,
			Message:     "Smali method has no instructions",
			ManualCheck: true,
		})
		return result
	}

	statuses := []model.Confidence{}
	for name, other := range decompilers {
		dmr := compareOne(smali, other, name)
		result.Decompilers[name] = dmr
		statuses = append(statuses, dmr.Status)
		result.Issues = append(result.Issues, dmr.Issues...)
	}

	result.Status = aggregate(statuses)
	result.Verdict = verdictText(result)
	return result
}

func compareOne(truth, other *ir.MethodIR, name string) model.DecompilerMethodResult {
	out := model.DecompilerMethodResult{Name: name}
	if other == nil {
		out.Status = model.ConfidenceUnresolved
		out.Note = "method not found in decompiler output"
		out.Issues = append(out.Issues, model.Issue{
			Type:        model.IssueInsufficientEvidence,
			Severity:    model.SeverityMedium,
			Decompiler:  name,
			Message:     fmt.Sprintf("%s did not produce this method", name),
			ManualCheck: true,
		})
		return out
	}
	out.SourcePath = other.SourcePath

	var issues []model.Issue
	partial := false
	disagree := false

	// CFG comparison
	sc := cfg.CompareStructure(truth.ControlFlow, other.ControlFlow)
	if !sc.Compatible {
		disagree = true
		issues = append(issues, model.Issue{
			Type:        model.IssueCFGDifference,
			Severity:    model.SeverityHigh,
			Decompiler:  name,
			Message:     "control-flow reconstruction differs from bytecode",
			Evidence:    strings.Join(sc.Notes, "; "),
			ManualCheck: true,
		})
	} else if len(sc.Notes) > 0 {
		partial = true
		issues = append(issues, model.Issue{
			Type:       model.IssueCFGDifference,
			Severity:   model.SeverityLow,
			Decompiler: name,
			Message:    "minor CFG variance within tolerance",
			Evidence:   strings.Join(sc.Notes, "; "),
		})
	}

	// Call-set comparison (by name; descriptors often unavailable from Java AST)
	callCompat, callEvidence := compareCallSets(truth.Calls, other.Calls)
	switch callCompat {
	case model.ConfidenceDisagreement:
		disagree = true
		issues = append(issues, model.Issue{
			Type:        model.IssueCallDifference,
			Severity:    model.SeverityHigh,
			Decompiler:  name,
			Message:     "call sites differ from bytecode",
			Evidence:    callEvidence,
			ManualCheck: true,
		})
	case model.ConfidencePartiallyConsistent:
		partial = true
		issues = append(issues, model.Issue{
			Type:       model.IssueCallDifference,
			Severity:   model.SeverityMedium,
			Decompiler: name,
			Message:    "call sites partially compatible with bytecode",
			Evidence:   callEvidence,
		})
	}

	// Exception handlers
	tEx, oEx := len(truth.Exceptions), len(other.Exceptions)
	if tEx > 0 && oEx == 0 {
		partial = true
		issues = append(issues, model.Issue{
			Type:        model.IssueExceptionFlowDiff,
			Severity:    model.SeverityMedium,
			Decompiler:  name,
			Message:     "bytecode has exception handlers; reconstruction shows none",
			Evidence:    fmt.Sprintf("truth=%d other=%d", tEx, oEx),
			ManualCheck: true,
		})
	} else if abs(tEx-oEx) > 1 {
		disagree = true
		issues = append(issues, model.Issue{
			Type:        model.IssueExceptionFlowDiff,
			Severity:    model.SeverityHigh,
			Decompiler:  name,
			Message:     "exception handler count differs significantly from bytecode",
			Evidence:    fmt.Sprintf("truth=%d other=%d", tEx, oEx),
			ManualCheck: true,
		})
	}

	// Return count heuristic
	ts, os := truth.Summary(), other.Summary()
	if ts.Returns > 0 && os.Returns == 0 && os.Instructions > 0 {
		partial = true
		issues = append(issues, model.Issue{
			Type:       model.IssueReturnFlowDiff,
			Severity:   model.SeverityMedium,
			Decompiler: name,
			Message:    "return flow not detected in reconstruction",
			Evidence:   fmt.Sprintf("truth_returns=%d other_returns=%d", ts.Returns, os.Returns),
		})
	}

	out.Issues = issues
	switch {
	case disagree:
		out.Status = model.ConfidenceDisagreement
	case partial:
		out.Status = model.ConfidencePartiallyConsistent
	default:
		out.Status = model.ConfidenceConsistent
		out.Note = "structurally compatible with bytecode evidence"
	}
	return out
}

func compareCallSets(truth, other []ir.Call) (model.Confidence, string) {
	if len(truth) == 0 && len(other) == 0 {
		return model.ConfidenceConsistent, ""
	}
	tNames := nameSet(truth)
	oNames := nameSet(other)
	missing := diffKeys(tNames, oNames)
	extra := diffKeys(oNames, tNames)

	// Compare by method name only (owner often differs in Java AST vs smali).
	tByName := countByName(truth)
	oByName := countByName(other)
	nameMissing := 0
	for n, c := range tByName {
		if oByName[n] < c {
			nameMissing += c - oByName[n]
		}
	}

	if len(truth) == 0 {
		return model.ConfidencePartiallyConsistent, "no invokes in bytecode; reconstruction has calls"
	}
	overlap := 0
	for n := range tByName {
		if oByName[n] > 0 {
			overlap++
		}
	}
	ratio := float64(overlap) / float64(len(tByName))
	evidence := fmt.Sprintf("truth_calls=%d other_calls=%d name_overlap=%.0f%% missing_names=%v",
		len(truth), len(other), ratio*100, truncateList(missing, 5))

	switch {
	case ratio >= 0.8 && nameMissing <= max(1, len(truth)/5):
		if len(extra) > 0 {
			return model.ConfidencePartiallyConsistent, evidence + "; extras=" + strings.Join(truncateList(extra, 3), ",")
		}
		return model.ConfidenceConsistent, evidence
	case ratio >= 0.4:
		return model.ConfidencePartiallyConsistent, evidence
	default:
		return model.ConfidenceDisagreement, evidence
	}
}

func nameSet(calls []ir.Call) map[string]struct{} {
	m := map[string]struct{}{}
	for _, c := range calls {
		key := c.Name
		if c.Owner != "" {
			key = c.Owner + "." + c.Name
		}
		m[key] = struct{}{}
	}
	return m
}

func countByName(calls []ir.Call) map[string]int {
	m := map[string]int{}
	for _, c := range calls {
		m[c.Name]++
	}
	return m
}

func diffKeys(a, b map[string]struct{}) []string {
	var out []string
	for k := range a {
		if _, ok := b[k]; !ok {
			out = append(out, k)
		}
	}
	return out
}

func truncateList(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return append(in[:n], "…")
}

func aggregate(statuses []model.Confidence) model.Confidence {
	if len(statuses) == 0 {
		return model.ConfidenceUnresolved
	}
	hasDisagree, hasPartial, hasUnresolved, hasConsistent := false, false, false, false
	for _, s := range statuses {
		switch s {
		case model.ConfidenceDisagreement:
			hasDisagree = true
		case model.ConfidencePartiallyConsistent:
			hasPartial = true
		case model.ConfidenceUnresolved, model.ConfidenceInsufficientEvidence, model.ConfidenceToolFailure, model.ConfidenceParseFailure:
			hasUnresolved = true
		case model.ConfidenceConsistent:
			hasConsistent = true
		}
	}
	switch {
	case hasDisagree:
		return model.ConfidenceDisagreement
	case hasPartial:
		return model.ConfidencePartiallyConsistent
	case hasConsistent && !hasUnresolved:
		return model.ConfidenceConsistent
	case hasConsistent:
		return model.ConfidencePartiallyConsistent
	default:
		return model.ConfidenceUnresolved
	}
}

func verdictText(r model.MethodResult) string {
	switch r.Status {
	case model.ConfidenceConsistent:
		return "Available reconstructions are structurally compatible with the underlying DEX/Smali."
	case model.ConfidencePartiallyConsistent:
		return "Core behavior appears compatible, but some aspects differ or lack evidence. Manual inspection recommended."
	case model.ConfidenceDisagreement:
		return "One or more reconstructions differ from bytecode in control flow, calls, or exception handling. Do not trust a single decompiler output."
	case model.ConfidenceUnresolved:
		return "Insufficient decompiler output to form a verdict. Smali remains the source of truth."
	default:
		return "Evidence insufficient for a confident verdict."
	}
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// IndexByFuzzyKey indexes methods for cross-matching when descriptors differ.
func IndexByFuzzyKey(methods []*ir.MethodIR) map[string][]*ir.MethodIR {
	m := map[string][]*ir.MethodIR{}
	for _, method := range methods {
		if method == nil {
			continue
		}
		key := fuzzyKey(method.ClassName, method.MethodName)
		m[key] = append(m[key], method)
	}
	return m
}

func fuzzyKey(class, name string) string {
	class = strings.ReplaceAll(class, "/", ".")
	return strings.ToLower(class) + "->" + name
}

// Match finds the best decompiler method for a Smali method.
func Match(smali *ir.MethodIR, index map[string][]*ir.MethodIR) *ir.MethodIR {
	cands := index[fuzzyKey(smali.ClassName, smali.MethodName)]
	if len(cands) == 0 {
		return nil
	}
	if len(cands) == 1 {
		return cands[0]
	}
	// Prefer matching parameter arity.
	best := cands[0]
	bestScore := -1
	for _, c := range cands {
		score := 0
		if len(c.Parameters) == len(smali.Parameters) {
			score += 2
		}
		if string(c.ReturnType) != "" && string(c.ReturnType) == string(smali.ReturnType) {
			score++
		}
		if score > bestScore {
			bestScore = score
			best = c
		}
	}
	return best
}
