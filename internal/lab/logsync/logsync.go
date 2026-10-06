// Package logsync imports device logcat into a Lab session timeline.
package logsync

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/armin/apkcheck/internal/lab/session"
	"github.com/armin/apkcheck/internal/runtime/adb"
)

// Clear wipes the device logcat buffer so the next capture starts clean.
func Clear(ctx context.Context, client *adb.Client, serial string) error {
	if client == nil || serial == "" {
		return fmt.Errorf("adb client and serial required")
	}
	_, err := client.Shell(ctx, serial, "logcat", "-c")
	return err
}

// ImportOptions controls logcat → timeline import.
type ImportOptions struct {
	Package string // target app package — matching lines become category=app
	Limit   int    // max lines to scan (default 800)
	MaxEv   int    // max events to append (default 200)
}

// Import dumps logcat since buffer clear and appends kernel / app / runtime events
// onto the run timeline, aligned to run.StartedAt.
func Import(ctx context.Context, client *adb.Client, serial string, sess *session.Manager, run *session.Run, opt ImportOptions) (int, error) {
	if client == nil || serial == "" || sess == nil || run == nil {
		return 0, fmt.Errorf("client, serial, session, run required")
	}
	if opt.Limit <= 0 {
		opt.Limit = 800
	}
	if opt.MaxEv <= 0 {
		opt.MaxEv = 200
	}
	out, err := client.Shell(ctx, serial, "logcat", "-d", "-v", "epoch", "-t", strconv.Itoa(opt.Limit))
	if err != nil {
		return 0, err
	}
	pkg := strings.TrimSpace(opt.Package)
	if pkg == "" {
		pkg = strings.TrimSpace(run.Package)
	}
	startUnix := float64(run.StartedAt.UnixNano()) / 1e9
	n := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		ts, rest, ok := splitEpochLine(line)
		if !ok {
			continue
		}
		if ts+0.05 < startUnix { // slightly before run start is noise
			continue
		}
		offset := int64((ts - startUnix) * 1000)
		if offset < 0 {
			offset = 0
		}
		cat, tags, typ := classifyLogLine(rest, pkg)
		if cat == "" {
			continue
		}
		msg := rest
		if len(msg) > 220 {
			msg = msg[:220] + "…"
		}
		ev := session.Event{
			Type: typ, Source: "logcat", Category: cat,
			Message: msg, Tags: tags, OffsetMS: offset,
			Metadata: map[string]any{
				"raw_ts": ts, "package": pkg, "preserve_offset": true,
			},
		}
		if _, err := sess.AddEvent(run.ID, ev); err != nil {
			continue
		}
		n++
		if n >= opt.MaxEv {
			break
		}
	}
	return n, nil
}

func splitEpochLine(line string) (ts float64, rest string, ok bool) {
	// Format: "1728000000.123456  priority/tag: message" or "1728000000.123  I/tag: …"
	sp := strings.IndexByte(line, ' ')
	if sp <= 0 {
		return 0, "", false
	}
	head := line[:sp]
	f, err := strconv.ParseFloat(head, 64)
	if err != nil || f < 1_000_000_000 {
		return 0, "", false
	}
	return f, strings.TrimSpace(line[sp+1:]), true
}

func classifyLogLine(rest, pkg string) (category string, tags []string, typ string) {
	low := strings.ToLower(rest)
	pkgLow := strings.ToLower(pkg)

	// IME/jank noise — not app bugs; "PREDICTION_ERROR" was inflating Live Log err counts.
	if strings.Contains(rest, "FrameTracker") ||
		strings.Contains(rest, "PREDICTION_ERROR") ||
		strings.Contains(low, "ime_insets_animation") {
		return "", nil, ""
	}

	switch {
	case strings.Contains(low, "kernel") ||
		strings.HasPrefix(rest, "K/") ||
		strings.Contains(rest, "/Kernel") ||
		strings.Contains(rest, "lowmemorykiller") ||
		strings.Contains(rest, "DEBUG") && strings.Contains(low, "tombstone"):
		return "kernel", []string{"kernel", "android"}, "KERNEL_LOG"
	case strings.Contains(rest, "AndroidRuntime") && strings.Contains(low, "fatal"):
		return "kernel", []string{"kernel", "crash"}, "RUNTIME_FATAL"
	case strings.Contains(low, "apkcheck-harness") || strings.Contains(low, "testharness") ||
		strings.Contains(low, "probe_launch") || strings.Contains(low, "probe_view") || strings.Contains(low, "probe_start"):
		return "process", []string{"harness", "attack", "process"}, "HARNESS_LOG"
	case pkgLow != "" && strings.Contains(low, pkgLow):
		short := pkg
		if i := strings.LastIndex(pkg, "."); i >= 0 && i+1 < len(pkg) {
			short = pkg[i+1:]
		}
		tags := []string{"app"}
		if short != "" && short != "app" {
			tags = append(tags, short)
		}
		typ := "APP_LOG"
		if strings.Contains(rest, "ActivityManager") || strings.Contains(rest, "ActivityTaskManager") {
			typ = "APP_LIFECYCLE"
			tags = append(tags, "lifecycle")
		}
		return "app", tags, typ
	default:
		return "", nil, ""
	}
}

// WarmRecording pauses so screenrecord is capturing before the first UI action.
func WarmRecording(d time.Duration) {
	if d <= 0 {
		d = 2 * time.Second
	}
	time.Sleep(d)
}
