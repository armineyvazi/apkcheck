package timeline_test

import (
	"strings"
	"testing"
	"time"

	"github.com/armin/apkcheck/internal/runtime/timeline"
)

func TestTimelineOrderAndFormat(t *testing.T) {
	b := timeline.New(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	b.Add("install", "ok", "RUNTIME_OBSERVATION")
	time.Sleep(2 * time.Millisecond)
	b.Add("launch", "ok", "RUNTIME_OBSERVATION")
	ev := b.Sorted()
	if len(ev) != 2 {
		t.Fatal(ev)
	}
	txt := timeline.FormatText(ev)
	if !strings.Contains(txt, "install") || !strings.Contains(txt, "launch") {
		t.Fatal(txt)
	}
}
