// Package process collects runtime process information.
package process

import (
	"context"
	"strings"

	"github.com/armin/apkcheck/internal/runtime/adb"
)

// Info is process evidence for a package.
type Info struct {
	PID     string `json:"pid,omitempty"`
	UID     string `json:"uid,omitempty"`
	Name    string `json:"name,omitempty"`
	Package string `json:"package,omitempty"`
	RawPS   string `json:"raw_ps,omitempty"`
}

// Collect gathers PID/UID for a package.
func Collect(ctx context.Context, client *adb.Client, serial, pkg string) (*Info, error) {
	info := &Info{Package: pkg, Name: pkg}
	if pkg == "" {
		return info, nil
	}
	pid, err := client.Shell(ctx, serial, "pidof", pkg)
	if err == nil {
		pid = strings.TrimSpace(pid)
		// pidof may return multiple PIDs; take the first.
		if i := strings.IndexByte(pid, ' '); i >= 0 {
			pid = pid[:i]
		}
		info.PID = pid
	}
	if info.PID != "" {
		// dumpsys package for user id is heavier; try ps -A
		ps, _ := client.Shell(ctx, serial, "ps", "-A")
		info.RawPS = ""
		for _, line := range strings.Split(ps, "\n") {
			if strings.Contains(line, pkg) || (info.PID != "" && strings.Contains(line, info.PID)) {
				info.RawPS = strings.TrimSpace(line)
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					info.UID = fields[0]
				}
				break
			}
		}
	}
	return info, nil
}
