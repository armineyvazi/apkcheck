package doctor_test

import (
	"context"
	"testing"

	"github.com/armin/apkcheck/internal/decompiler"
	"github.com/armin/apkcheck/internal/doctor"
)

func TestDoctorRuns(t *testing.T) {
	r := doctor.Check(context.Background(), decompiler.Paths{})
	if r == nil {
		t.Fatal("nil")
	}
	if len(r.Tools) < 3 {
		t.Fatalf("tools=%d", len(r.Tools))
	}
}
