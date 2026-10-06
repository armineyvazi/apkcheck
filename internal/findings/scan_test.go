package findings_test

import (
	"testing"

	"github.com/armin/apkcheck/internal/findings"
	"github.com/armin/apkcheck/internal/ir"
	"github.com/armin/apkcheck/pkg/model"
)

func TestScanExportedAndSecrets(t *testing.T) {
	debuggable := true
	cleartext := true
	info := model.APKInfo{
		Path:               "app.apk",
		ExportedActivities: []string{"com.example.LoginActivity"},
		ExportedProviders:  []string{"com.example.SecretProvider"},
		Permissions:        []string{"android.permission.CAMERA"},
		Debuggable:         &debuggable,
		UsesCleartext:      &cleartext,
	}
	methods := []*ir.MethodIR{{
		ClassName:  "com.example.Config",
		MethodName: "keys",
		Constants:  []ir.Constant{{Kind: "string", Value: `api_key="AIzaSyA-test-key-012345678901234567890123"`}},
	}}
	fs := findings.Scan(findings.Input{APK: info, MethodIR: methods})
	if len(fs) < 4 {
		t.Fatalf("expected multiple findings, got %d: %+v", len(fs), fs)
	}
	var sawStatic, sawInference bool
	for _, f := range fs {
		if f.Class == model.EvidenceStatic {
			sawStatic = true
		}
		if f.Class == model.EvidenceInference {
			sawInference = true
		}
		if f.Class == model.EvidenceStatic && f.Category == model.CatHardcodedSecret {
			if f.Confidence == model.ConfidenceSourceOfTruth {
				t.Fatal("secrets must not claim SOURCE_OF_TRUTH")
			}
		}
	}
	if !sawStatic {
		t.Fatal("expected STATIC_EVIDENCE findings")
	}
	_ = sawInference
}

func TestSemanticAnnotate(t *testing.T) {
	// imported via separate package test in semantic — keep findings focused
}
