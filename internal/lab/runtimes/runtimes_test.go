package runtimes_test

import (
	"context"
	"testing"
	"time"

	"github.com/armin/apkcheck/internal/lab/runtimes"
)

func TestSnapshot(t *testing.T) {
	mgr := &runtimes.Manager{}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	st, err := mgr.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st == nil {
		t.Fatal("nil status")
	}
	t.Logf("avds=%d running=%d devices=%d", st.AVDConfigured, st.EmulatorsRunning, st.DevicesOnline)
}
