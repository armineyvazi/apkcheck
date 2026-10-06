package cfg_test

import (
	"testing"

	"github.com/armin/apkcheck/internal/cfg"
	"github.com/armin/apkcheck/internal/ir"
)

func TestBuildAndCompare(t *testing.T) {
	m := &ir.MethodIR{
		Instructions: []ir.Instruction{
			{Index: 0, Opcode: "const/4", Operands: []string{"v0", "0x1"}},
			{Index: 1, Opcode: "if-eqz", Operands: []string{"v0", ":cond_0"}, Targets: []string{"cond_0"}},
			{Index: 2, Opcode: "invoke-virtual", Operands: []string{"{v0}", "LFoo;->a()V"}},
			{Index: 3, Opcode: "return-void"},
			{Index: 4, Label: "cond_0", Opcode: "return-void"},
		},
	}
	g := cfg.Build(m)
	if g.Entry == "" {
		t.Fatal("empty entry")
	}
	if len(g.Blocks) < 2 {
		t.Fatalf("blocks=%d", len(g.Blocks))
	}
	if g.BranchCount != 1 {
		t.Fatalf("branches=%d", g.BranchCount)
	}

	other := &ir.MethodIR{
		Instructions: []ir.Instruction{
			{Index: 0, Opcode: "if", Label: "L0", Targets: []string{"L1"}},
			{Index: 1, Opcode: "invoke", Label: "L1"},
			{Index: 2, Opcode: "return", Label: "L2"},
			{Index: 3, Opcode: "return", Label: "L3"},
		},
	}
	cfg.Build(other)
	sc := cfg.CompareStructure(m.ControlFlow, other.ControlFlow)
	if !sc.Compatible {
		t.Fatalf("expected compatible, notes=%v", sc.Notes)
	}
}
