package compare_test

import (
	"testing"

	"github.com/armin/apkcheck/internal/lab"
	"github.com/armin/apkcheck/internal/lab/compare"
)

func TestArtifactsCompare(t *testing.T) {
	a := &lab.Artifact{ID: "1", Kind: lab.KindOriginalAPK, Package: "com.a", SHA256: "aaa"}
	b := &lab.Artifact{ID: "2", Kind: lab.KindSignedAPK, Package: "com.a", SHA256: "bbb"}
	r := compare.Artifacts(a, b)
	if r.LeftID != "1" || r.RightID != "2" {
		t.Fatalf("%+v", r)
	}
	found := false
	for _, m := range r.Metrics {
		if m.Name == "package" && m.Equal {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected package equal: %+v", r.Metrics)
	}
}

func TestValidateResults(t *testing.T) {
	a := &lab.Artifact{ID: "1", Kind: lab.KindOriginalAPK, Package: "com.a"}
	b := &lab.Artifact{ID: "2", Kind: lab.KindSignedAPK, Package: "com.a"}
	lv := &lab.ValidateResult{OK: true, Stages: []lab.ValidateStage{{Name: "launch", OK: true}}}
	rv := &lab.ValidateResult{OK: false, Stages: []lab.ValidateStage{{Name: "launch", OK: false, Error: "crash"}}}
	r := compare.ValidateResults(a, b, lv, rv)
	if len(r.Metrics) < 2 {
		t.Fatalf("%+v", r)
	}
}
