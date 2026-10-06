package semantic_test

import (
	"testing"

	"github.com/armin/apkcheck/internal/semantic"
	"github.com/armin/apkcheck/pkg/model"
)

func TestAssessConsistentHigh(t *testing.T) {
	m := model.MethodResult{
		Ref:    model.MethodRef{Class: "a.B", Name: "c"},
		Status: model.ConfidenceConsistent,
		Decompilers: map[string]model.DecompilerMethodResult{
			"jadx": {Name: "jadx", Status: model.ConfidenceConsistent},
			"cfr":  {Name: "cfr", Status: model.ConfidenceConsistent},
		},
		Smali: &model.SmaliSummary{Instructions: 10, BasicBlocks: 3, Branches: 1, Calls: 2, Returns: 1},
	}
	a := semantic.AssessMethod(m)
	if a.Confidence != model.SemanticHigh {
		t.Fatalf("got %s want HIGH", a.Confidence)
	}
	if !a.BehaviorallyEquiv || !a.SyntacticallyValid {
		t.Fatal("expected behavioral + syntactic valid")
	}
}

func TestAssessDisagreementLow(t *testing.T) {
	m := model.MethodResult{
		Ref:    model.MethodRef{Class: "a.B", Name: "c"},
		Status: model.ConfidenceDisagreement,
		Decompilers: map[string]model.DecompilerMethodResult{
			"jadx": {Status: model.ConfidenceDisagreement},
			"cfr":  {Status: model.ConfidenceConsistent},
		},
	}
	a := semantic.AssessMethod(m)
	if a.Confidence != model.SemanticLow {
		t.Fatalf("got %s want LOW", a.Confidence)
	}
	if a.BehaviorallyEquiv {
		t.Fatal("disagreement must not claim behavioral equivalence")
	}
}
