package diff_test

import (
	"testing"

	"github.com/armin/apkcheck/internal/cfg"
	"github.com/armin/apkcheck/internal/diff"
	"github.com/armin/apkcheck/internal/ir"
	"github.com/armin/apkcheck/pkg/model"
)

func TestCompareConsistent(t *testing.T) {
	smali := &ir.MethodIR{
		ClassName:  "com.example.Auth",
		MethodName: "authenticate",
		Descriptor: "(Ljava/lang/String;)Z",
		Instructions: []ir.Instruction{
			{Opcode: "const-string"},
			{Opcode: "invoke-virtual", Operands: []string{"Ljava/lang/String;->equals(Ljava/lang/Object;)Z"}},
			{Opcode: "if-eqz", Targets: []string{"fail"}},
			{Opcode: "return"},
			{Label: "fail", Opcode: "return"},
		},
		Calls: []ir.Call{{Owner: "java.lang.String", Name: "equals", Descriptor: "(Ljava/lang/Object;)Z"}},
	}
	cfg.Build(smali)

	jadx := &ir.MethodIR{
		ClassName:  "com.example.Auth",
		MethodName: "authenticate",
		Instructions: []ir.Instruction{
			{Opcode: "if", Label: "L0", Targets: []string{"L1"}},
			{Opcode: "invoke", Label: "L1"},
			{Opcode: "return", Label: "L2"},
			{Opcode: "return", Label: "L3"},
		},
		Calls: []ir.Call{{Owner: "password", Name: "equals"}},
	}
	cfg.Build(jadx)

	res := diff.CompareMethod(smali, map[string]*ir.MethodIR{"jadx": jadx})
	if res.Status != model.ConfidenceConsistent && res.Status != model.ConfidencePartiallyConsistent {
		t.Fatalf("status=%s issues=%v", res.Status, res.Issues)
	}
}

func TestCompareMissingMethod(t *testing.T) {
	smali := &ir.MethodIR{
		ClassName:  "com.example.A",
		MethodName: "foo",
		Instructions: []ir.Instruction{
			{Opcode: "return-void"},
		},
	}
	cfg.Build(smali)
	res := diff.CompareMethod(smali, map[string]*ir.MethodIR{"jadx": nil})
	if res.Decompilers["jadx"].Status != model.ConfidenceUnresolved {
		t.Fatalf("got %s", res.Decompilers["jadx"].Status)
	}
}
