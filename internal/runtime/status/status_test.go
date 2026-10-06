package status_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/armin/apkcheck/internal/runtime/status"
)

func TestBannerAndPhases(t *testing.T) {
	var buf bytes.Buffer
	p := status.New(&buf)
	p.Banner("/tmp/app.apk", "emulator", "Pixel_8_API_34")
	p.Phase("System image & AVD")
	p.Warn("system image MISSING: /sdk/system-images/...")
	p.OK("AVD ready")
	out := buf.String()
	for _, want := range []string{"apkcheck runtime", "emulator", "Pixel_8_API_34", "MISSING", "ok"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}
