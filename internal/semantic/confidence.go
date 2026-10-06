// Package semantic assesses behavioral equivalence of decompiled methods vs Smali.
// Syntactic validity ≠ semantic correctness.
package semantic

import (
	"fmt"

	"github.com/armin/apkcheck/pkg/model"
)

// AssessMethod derives SEMANTIC_CONFIDENCE from existing comparison results.
func AssessMethod(m model.MethodResult) model.SemanticAssessment {
	a := model.SemanticAssessment{
		Ref:                m.Ref,
		SyntacticallyValid: true,
		Confidence:         model.SemanticUncertain,
	}

	var toolsOK, toolsFail, toolsDisagree int
	for name, d := range m.Decompilers {
		switch d.Status {
		case model.ConfidenceConsistent:
			toolsOK++
		case model.ConfidenceDisagreement, model.ConfidencePartiallyConsistent:
			toolsDisagree++
			a.DisagreeingTools = append(a.DisagreeingTools, name)
		case model.ConfidenceToolFailure, model.ConfidenceParseFailure:
			toolsFail++
			a.SyntacticallyValid = a.SyntacticallyValid && false
			a.Reasons = append(a.Reasons, fmt.Sprintf("%s: %s", name, d.Status))
		case model.ConfidenceUnresolved, model.ConfidenceInsufficientEvidence:
			a.Reasons = append(a.Reasons, fmt.Sprintf("%s: insufficient evidence", name))
		}
	}

	switch m.Status {
	case model.ConfidenceConsistent:
		if toolsOK > 0 && toolsDisagree == 0 && toolsFail == 0 {
			a.BehaviorallyEquiv = true
			a.Confidence = model.SemanticHigh
			a.Reasons = append(a.Reasons, "All available decompilers structurally consistent with Smali CFG/calls/returns")
		} else {
			a.BehaviorallyEquiv = true
			a.Confidence = model.SemanticMedium
			a.Reasons = append(a.Reasons, "Overall consistent; some tools missing or soft-failed")
		}
	case model.ConfidencePartiallyConsistent:
		a.BehaviorallyEquiv = false
		a.Confidence = model.SemanticMedium
		a.Reasons = append(a.Reasons, "Partial structural match — possible boolean/CFG rewrite; manual review advised")
	case model.ConfidenceDisagreement:
		a.BehaviorallyEquiv = false
		a.Confidence = model.SemanticLow
		a.Reasons = append(a.Reasons, "Material disagreement between reconstructions and/or Smali")
	default:
		a.BehaviorallyEquiv = false
		a.Confidence = model.SemanticUncertain
		a.Reasons = append(a.Reasons, "Unresolved — successful decompilation is not assumed")
	}

	if m.Smali != nil {
		a.SmaliEvidence = append(a.SmaliEvidence,
			fmt.Sprintf("instructions=%d blocks=%d branches=%d calls=%d returns=%d throws=%d",
				m.Smali.Instructions, m.Smali.BasicBlocks, m.Smali.Branches,
				m.Smali.Calls, m.Smali.Returns, m.Smali.Throws),
		)
		for _, iss := range m.Issues {
			if iss.Evidence != "" {
				a.SmaliEvidence = append(a.SmaliEvidence, iss.Evidence)
			} else if iss.Message != "" {
				a.SmaliEvidence = append(a.SmaliEvidence, iss.Message)
			}
		}
	}

	// Native methods cannot be semantically equated to Java reconstructions.
	if m.NativeBridge {
		a.BehaviorallyEquiv = false
		a.Confidence = model.SemanticUncertain
		a.Reasons = append(a.Reasons, "Native bridge — Java decompilers do not cover .so implementation")
	}

	return a
}

// AssessAll evaluates every method result.
func AssessAll(methods []model.MethodResult) []model.SemanticAssessment {
	out := make([]model.SemanticAssessment, 0, len(methods))
	for _, m := range methods {
		out = append(out, AssessMethod(m))
	}
	return out
}

// Annotate copies semantic confidence onto MethodResult fields.
func Annotate(methods []model.MethodResult) []model.MethodResult {
	for i := range methods {
		a := AssessMethod(methods[i])
		methods[i].SemanticConfidence = a.Confidence
		if len(a.Reasons) > 0 {
			methods[i].SemanticNote = a.Reasons[0]
		}
	}
	return methods
}
