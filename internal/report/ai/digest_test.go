package ai_test

import (
	"encoding/json"
	"testing"
	"time"

	aireport "github.com/armin/apkcheck/internal/report/ai"
	"github.com/armin/apkcheck/pkg/model"
)

func TestFromResultPrioritizesDisagreements(t *testing.T) {
	r := &model.AnalysisResult{
		SchemaVersion: model.SchemaVersion,
		ToolVersion:   "0.4.2",
		GeneratedAt:   time.Now().UTC(),
		APK:           model.APKInfo{Path: "app.apk", Package: "com.example"},
		Summary: model.AnalysisSummary{
			MethodsAnalyzed: 3, MethodsDisagreement: 1, MethodsPartial: 1, SecurityRelevant: 1,
		},
		Methods: []model.MethodResult{
			{
				Ref:    model.MethodRef{Class: "com.example.A", Name: "ok"},
				Status: model.ConfidenceConsistent, Verdict: "ok",
			},
			{
				Ref:    model.MethodRef{Class: "com.example.B", Name: "bad"},
				Status: model.ConfidenceDisagreement, Verdict: "branch mismatch",
				Issues: []model.Issue{{Type: "cfg", Message: "missing if"}},
			},
			{
				Ref:    model.MethodRef{Class: "com.example.C", Name: "auth"},
				Status: model.ConfidencePartiallyConsistent, SecurityRelevant: true,
				SecurityTags: []string{"crypto"}, Verdict: "partial",
			},
		},
		Limitations: []string{"test lim"},
	}
	d := aireport.FromResult(r, aireport.Options{MaxFindings: 10})
	if d.Schema != aireport.Schema {
		t.Fatalf("schema %s", d.Schema)
	}
	if len(d.Disagreements) < 1 {
		t.Fatal("expected disagreements")
	}
	if d.Disagreements[0].Method == "" {
		t.Fatal("empty method")
	}
	if len(d.Security) < 1 {
		t.Fatal("expected security hotspot")
	}
	if len(d.NextActions) == 0 {
		t.Fatal("expected next actions")
	}
	if len(d.Principles) == 0 {
		t.Fatal("expected principles")
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(raw) {
		t.Fatal("invalid json")
	}
}

func TestFromNilResult(t *testing.T) {
	d := aireport.FromResult(nil, aireport.Options{})
	if d == nil || len(d.NextActions) == 0 {
		t.Fatal("nil digest")
	}
}
