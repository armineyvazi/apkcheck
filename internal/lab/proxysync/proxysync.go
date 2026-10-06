// Package proxysync imports mitmproxy flow JSONL into a Lab session timeline.
package proxysync

import (
	"fmt"

	"github.com/armin/apkcheck/internal/lab/proxy"
	"github.com/armin/apkcheck/internal/lab/session"
)

// Import reads flows.jsonl from proxyDir and appends MITM_HTTP events onto the run
// timeline (category=network), aligned to run.StartedAt.
func Import(proxyDir string, sess *session.Manager, run *session.Run) int {
	if proxyDir == "" || sess == nil || run == nil {
		return 0
	}
	flows, err := proxy.ReadFlowJSONL(proxyDir)
	if err != nil || len(flows) == 0 {
		return 0
	}
	flows = proxy.AlignOffsets(flows, run.StartedAt)
	n := 0
	for _, f := range flows {
		msg := fmt.Sprintf("%s %s → %d", f.Method, f.URL, f.Status)
		tags := append([]string{}, f.Tags...)
		if len(tags) == 0 {
			tags = []string{"mitm"}
		}
		ev := session.Event{
			Type: "MITM_HTTP", Source: "network", Category: "network",
			Message: msg, Tags: tags, OffsetMS: f.OffsetMS,
			Metadata: map[string]any{
				"method": f.Method, "host": f.Host, "url": f.URL,
				"path": f.Path, "status": f.Status, "tags": tags,
				"preserve_offset": true,
			},
		}
		if _, err := sess.AddEvent(run.ID, ev); err == nil {
			n++
		}
	}
	return n
}
