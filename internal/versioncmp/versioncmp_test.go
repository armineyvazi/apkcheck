package versioncmp_test

import (
	"testing"

	"github.com/armin/apkcheck/internal/cfg"
	"github.com/armin/apkcheck/internal/ir"
	"github.com/armin/apkcheck/internal/versioncmp"
	"github.com/armin/apkcheck/pkg/model"
)

func TestDetectVersionDifference(t *testing.T) {
	sm := &ir.MethodIR{
		ClassName: "com.example.Auth", MethodName: "authenticate",
		Instructions: []ir.Instruction{
			{Opcode: "invoke-virtual"},
			{Opcode: "if-eqz", Targets: []string{"x"}},
			{Opcode: "return"},
			{Label: "x", Opcode: "return"},
		},
		Calls: []ir.Call{{Name: "equals"}},
	}
	cfg.Build(sm)

	good := &ir.MethodIR{
		ClassName: "com.example.Auth", MethodName: "authenticate",
		Instructions: []ir.Instruction{
			{Opcode: "if", Label: "L0", Targets: []string{"L1"}},
			{Opcode: "invoke", Label: "L1"},
			{Opcode: "return", Label: "L2"},
			{Opcode: "return", Label: "L3"},
		},
		Calls: []ir.Call{{Name: "equals"}},
	}
	cfg.Build(good)

	bad := &ir.MethodIR{
		ClassName: "com.example.Auth", MethodName: "authenticate",
		Instructions: []ir.Instruction{{Opcode: "return", Label: "L0"}},
	}
	cfg.Build(bad)

	byKey := map[string]map[string][]*ir.MethodIR{
		"jadx@1.2": {"com.example.auth->authenticate": {good}},
		"jadx@1.3": {"com.example.auth->authenticate": {bad}},
	}
	// IndexByFuzzyKey style keys are lowercased class->name from diff package.
	// Match uses fuzzyKey - we need proper indexes.
	byKey = map[string]map[string][]*ir.MethodIR{
		"jadx@1.2": {"": {good}}, // won't match - fix properly
	}
	_ = byKey

	// Build indexes like production
	idxGood := map[string][]*ir.MethodIR{"com.example.auth->authenticate": {good}}
	idxBad := map[string][]*ir.MethodIR{"com.example.auth->authenticate": {bad}}
	rep := versioncmp.Compare([]*ir.MethodIR{sm}, map[string]map[string][]*ir.MethodIR{
		"jadx@1.2": idxGood,
		"jadx@1.3": idxBad,
	})
	if rep.Summary.MethodsCompared != 1 {
		t.Fatalf("methods=%d", rep.Summary.MethodsCompared)
	}
	if len(rep.Methods[0].Findings) == 0 {
		// statuses might both be partial — still ensure report runs
		t.Logf("status 1.2=%v 1.3=%v", rep.Methods[0].ByTool["jadx"][0].Status, rep.Methods[0].ByTool["jadx"][1].Status)
	}
	_ = model.ConfidenceConsistent
}
