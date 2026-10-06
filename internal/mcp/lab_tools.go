package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/armin/apkcheck/internal/lab"
	"github.com/armin/apkcheck/internal/lab/authgate"
	"github.com/armin/apkcheck/internal/lab/certs"
	"github.com/armin/apkcheck/internal/lab/compare"
	"github.com/armin/apkcheck/internal/lab/events"
	fridapkg "github.com/armin/apkcheck/internal/lab/frida"
	"github.com/armin/apkcheck/internal/lab/iocscan"
	"github.com/armin/apkcheck/internal/lab/logsync"
	"github.com/armin/apkcheck/internal/lab/pipeline"
	"github.com/armin/apkcheck/internal/lab/proxy"
	"github.com/armin/apkcheck/internal/lab/proxysync"
	"github.com/armin/apkcheck/internal/lab/recording"
	"github.com/armin/apkcheck/internal/lab/runtimes"
	"github.com/armin/apkcheck/internal/lab/scenarios"
	"github.com/armin/apkcheck/internal/lab/security"
	"github.com/armin/apkcheck/internal/lab/session"
	"github.com/armin/apkcheck/internal/lab/workspace"
	"github.com/armin/apkcheck/internal/runner"
	"github.com/armin/apkcheck/internal/runtime/adb"
)

// labCtx detaches long Lab work from the MCP request lifetime so client
// disconnect / tool timeout churn does not kill emulator boot or rebuild.
func labCtx(_ context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		d = 30 * time.Minute
	}
	return context.WithTimeout(context.Background(), d)
}

func openLabPipe(workspace string) (*lab.Store, *pipeline.Pipeline, *events.Bus, error) {
	if workspace == "" {
		workspace = "./lab-data"
	}
	bus := events.NewBus(500)
	store, err := lab.OpenStore(workspace, bus)
	if err != nil {
		return nil, nil, nil, err
	}
	return store, &pipeline.Pipeline{Store: store, Bus: bus}, bus, nil
}

func openLabSession(workspace string) (*lab.Store, *pipeline.Pipeline, *events.Bus, *session.Manager, *recording.Manager, error) {
	store, pipe, bus, err := openLabPipe(workspace)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	sess := session.NewManager(store.Root, bus)
	rec := recording.NewManager(store.Root, bus, sess)
	return store, pipe, bus, sess, rec, nil
}

// runRec binds a Lab session + optional device recording for one MCP operation.
type runRec struct {
	Run    *session.Run
	Rec    *recording.Artifact
	Sess   *session.Manager
	RecMgr *recording.Manager
}

// beginRunRecording starts a session and, when serial is available, device recording.
// It may boot bootAVD when serial is empty. Returns the resolved serial.
func beginRunRecording(ctx context.Context, sess *session.Manager, recMgr *recording.Manager, opt session.StartOptions, serial, profile, bootAVD string) (*runRec, string) {
	if profile == "" {
		profile = "balanced"
	}
	opt.Record = true
	opt.Profile = profile
	if opt.MCPSession == "" {
		opt.MCPSession = "mcp"
	}
	if serial == "" {
		serial = security.DiscoverDefaultSerial(ctx)
	}
	if serial == "" && bootAVD != "" && bootAVD != "(unknown AVD)" {
		ser, err := (&runtimes.Manager{}).Start(ctx, bootAVD, false, 10*time.Minute)
		if err == nil {
			serial = ser
		}
	}
	opt.RuntimeSerial = serial
	if opt.RuntimeAVD == "" {
		opt.RuntimeAVD = bootAVD
	}
	run, err := sess.Start(opt)
	if err != nil {
		return nil, serial
	}
	rr := &runRec{Run: run, Sess: sess, RecMgr: recMgr}
	if serial != "" {
		art, rerr := recMgr.Start(ctx, run, serial, recording.ParseProfile(profile))
		// Keep artifact even on failure so MCP/UI can surface recording_id + note.
		if art != nil {
			rr.Rec = art
		}
		if rerr != nil {
			msg := rerr.Error()
			if art != nil && art.Note != "" {
				msg = art.Note
			}
			_, _ = sess.AddEvent(run.ID, session.Event{
				Type: "RECORDING_FAILED", Source: "mcp", Category: "runtime", Level: "warn",
				Message: msg, Bookmark: true, Tags: []string{"recording"},
				Metadata: map[string]any{"recording_id": artIDOrEmpty(art)},
			})
		}
	} else {
		_, _ = sess.AddEvent(run.ID, session.Event{
			Type: "RECORDING_SKIPPED", Source: "mcp", Category: "runtime", Level: "warn",
			Message: "no device serial — session created without video",
		})
	}
	return rr, serial
}

func artIDOrEmpty(art *recording.Artifact) string {
	if art == nil {
		return ""
	}
	return art.ID
}

func mcpEventKey(e events.Event) string {
	if m, ok := e.Data.(map[string]any); ok {
		if id, ok := m["event_id"].(string); ok && id != "" {
			return id
		}
	}
	return fmt.Sprintf("%s|%s|%s|%s", e.RunID, e.Type, e.At.UTC().Format(time.RFC3339Nano), e.Message)
}

func mergeMCPEventFeed(parts ...[]events.Event) []events.Event {
	seen := map[string]struct{}{}
	out := make([]events.Event, 0, 64)
	for _, list := range parts {
		for _, e := range list {
			k := mcpEventKey(e)
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}

func (rr *runRec) add(ev session.Event) {
	if rr == nil || rr.Sess == nil || rr.Run == nil {
		return
	}
	if ev.Source == "" {
		ev.Source = "mcp"
	}
	_, _ = rr.Sess.AddEvent(rr.Run.ID, ev)
}

func (rr *runRec) finish(ctx context.Context, ok bool, note string, failAt int64) string {
	if rr == nil || rr.Run == nil {
		return ""
	}
	recID := ""
	if rr.RecMgr != nil {
		// Always attempt Stop when a live recorder may exist (even if Start
		// returned a failed artifact pointer with no live loop).
		if stopped, _ := rr.RecMgr.Stop(ctx, rr.Run.ID); stopped != nil {
			recID = stopped.ID
			rr.Rec = stopped
		}
	}
	if recID == "" && rr.Rec != nil {
		recID = rr.Rec.ID
	}
	if recID == "" {
		recID = rr.Run.RecordingID
	}
	if rr.Sess != nil {
		result := "PASSED"
		if !ok {
			result = "FAILED"
		}
		_, _ = rr.Sess.Complete(rr.Run.ID, ok, result, note, failAt)
	}
	return recID
}

func (rr *runRec) ids() (labRunID, recordingID string) {
	if rr == nil || rr.Run == nil {
		return "", ""
	}
	labRunID = rr.Run.ID
	if rr.Rec != nil {
		recordingID = rr.Rec.ID
	} else {
		recordingID = rr.Run.RecordingID
	}
	return labRunID, recordingID
}

func attachRunIDs(payload map[string]any, rr *runRec, recordingID string) {
	if payload == nil || rr == nil || rr.Run == nil {
		return
	}
	payload["lab_run_id"] = rr.Run.ID
	if recordingID != "" {
		payload["recording_id"] = recordingID
	} else if rr.Rec != nil {
		payload["recording_id"] = rr.Rec.ID
	}
}

func jsonOK(v any) (string, bool, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", true, err
	}
	return string(b), false, nil
}

func jsonErrPayload(v any) (string, bool, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", true, err
	}
	return string(b), true, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func artID(args map[string]any) string {
	return firstNonEmpty(strArg(args, "artifact_id", ""), strArg(args, "id", ""))
}

func apkPath(args map[string]any) string {
	p := firstNonEmpty(strArg(args, "apk", ""), strArg(args, "path", ""))
	if p == "" {
		return ""
	}
	if !filepath.IsAbs(p) {
		if abs, err := filepath.Abs(p); err == nil {
			return abs
		}
	}
	return p
}

func workspaceArg(args map[string]any) string {
	return strArg(args, "workspace", "./lab-data")
}

func withNext(payload map[string]any, next ...string) map[string]any {
	if len(next) > 0 {
		payload["next"] = next
	}
	return payload
}

func latestByKind(store *lab.Store, kind lab.Kind) *lab.Artifact {
	var best *lab.Artifact
	for _, a := range store.List() {
		if a.Kind != kind {
			continue
		}
		if best == nil || a.CreatedAt.After(best.CreatedAt) {
			best = a
		}
	}
	return best
}

func (s *Server) execLabTool(parent context.Context, name string, args map[string]any) (string, bool, error) {
	if args == nil {
		args = map[string]any{}
	}
	ws := workspaceArg(args)

	switch name {
	case "apkcheck_lab_help":
		return jsonOK(labHelpPayload())

	case "apkcheck_lab_status":
		return s.labStatus(ws)

	case "apkcheck_lab_workflow":
		return s.labWorkflow(parent, ws, args)

	case "apkcheck_lab_import":
		path := apkPath(args)
		if path == "" {
			return "", true, fmt.Errorf("apk (or path) required — absolute path preferred")
		}
		if st, err := os.Stat(path); err != nil || st.IsDir() {
			return "", true, fmt.Errorf("apk not found: %s", path)
		}
		_, pipe, _, err := openLabPipe(ws)
		if err != nil {
			return "", true, err
		}
		a, err := pipe.ImportAPK(path, strArg(args, "label", ""))
		if err != nil {
			return "", true, err
		}
		return jsonOK(withNext(map[string]any{
			"artifact": a,
			"hint":     "Use artifact.id as artifact_id for decompile/rebuild/validate/security",
		}, "apkcheck_lab_rebuild", "apkcheck_lab_workflow action=import_rebuild_validate"))

	case "apkcheck_lab_list":
		store, _, _, err := openLabPipe(ws)
		if err != nil {
			return "", true, err
		}
		list := store.List()
		if list == nil {
			list = []*lab.Artifact{}
		}
		return jsonOK(withNext(map[string]any{
			"workspace": store.Root,
			"count":     len(list),
			"artifacts": list,
		}, "apkcheck_lab_status"))

	case "apkcheck_lab_decompile":
		id := artID(args)
		if id == "" {
			return "", true, fmt.Errorf("artifact_id (or id) required")
		}
		ctx, cancel := labCtx(parent, 45*time.Minute)
		defer cancel()
		_, pipe, _, err := openLabPipe(ws)
		if err != nil {
			return "", true, err
		}
		a, err := pipe.Decompile(ctx, id)
		if err != nil {
			return "", true, err
		}
		return jsonOK(withNext(map[string]any{"artifact": a}, "apkcheck_lab_build", "apkcheck_lab_rebuild"))

	case "apkcheck_lab_rebuild":
		id := artID(args)
		if id == "" {
			return "", true, fmt.Errorf("artifact_id (or id) required — original APK id")
		}
		ctx, cancel := labCtx(parent, 45*time.Minute)
		defer cancel()
		_, pipe, _, err := openLabPipe(ws)
		if err != nil {
			return "", true, err
		}
		a, err := pipe.RebuildFull(ctx, id)
		if err != nil {
			return "", true, err
		}
		return jsonOK(withNext(map[string]any{
			"artifact": a,
			"warning":  "Rebuild file exists ≠ runtime success — call apkcheck_lab_validate next",
		}, "apkcheck_lab_validate", "apkcheck_lab_runtime_list"))

	case "apkcheck_lab_build":
		id := artID(args)
		if id == "" {
			return "", true, fmt.Errorf("artifact_id (or id) required — project id")
		}
		ctx, cancel := labCtx(parent, 45*time.Minute)
		defer cancel()
		_, pipe, _, err := openLabPipe(ws)
		if err != nil {
			return "", true, err
		}
		a, err := pipe.Build(ctx, id)
		if err != nil {
			return "", true, err
		}
		return jsonOK(withNext(map[string]any{"artifact": a}, "apkcheck_lab_sign"))

	case "apkcheck_lab_sign":
		id := artID(args)
		if id == "" {
			return "", true, fmt.Errorf("artifact_id (or id) required — unsigned APK id")
		}
		ctx, cancel := labCtx(parent, 20*time.Minute)
		defer cancel()
		_, pipe, _, err := openLabPipe(ws)
		if err != nil {
			return "", true, err
		}
		a, err := pipe.Sign(ctx, id)
		if err != nil {
			return "", true, err
		}
		return jsonOK(withNext(map[string]any{"artifact": a}, "apkcheck_lab_validate"))

	case "apkcheck_lab_validate":
		id := artID(args)
		if id == "" {
			return "", true, fmt.Errorf("artifact_id (or id) required — signed or original APK")
		}
		ctx, cancel := labCtx(parent, 30*time.Minute)
		defer cancel()
		_, pipe, _, sess, recMgr, err := openLabSession(ws)
		if err != nil {
			return "", true, err
		}
		serial := firstNonEmpty(strArg(args, "device_id", ""), strArg(args, "serial", ""))
		opt := pipeline.ValidateOptions{
			EmulatorAVD:  strArg(args, "emulator", "Pixel_8_API_34"),
			DeviceSerial: serial,
			Duration:     time.Duration(intArg(args, "duration_sec", 15)) * time.Second,
		}
		if opt.DeviceSerial != "" {
			opt.EmulatorAVD = ""
		}
		var rr *runRec
		if boolArg(args, "record", false) {
			rr, serial = beginRunRecording(ctx, sess, recMgr, session.StartOptions{
				Kind: session.KindValidate, ArtifactID: id,
			}, serial, strArg(args, "profile", "balanced"), strArg(args, "emulator", "Pixel_8_API_34"))
			if serial != "" {
				opt.DeviceSerial = serial
				opt.EmulatorAVD = ""
			}
			if rr != nil {
				rr.add(session.Event{
					Type: "VALIDATE_STARTED", Category: "runtime",
					Message: "mcp validate with recording",
				})
			}
		}
		res, err := pipe.Validate(ctx, id, opt)
		if rr != nil {
			if res != nil {
				res.LabRunID = rr.Run.ID
				if rr.Rec != nil {
					res.RecordingID = rr.Rec.ID
				}
				for _, st := range res.Stages {
					level := "info"
					if !st.OK {
						level = "error"
					}
					rr.add(session.Event{
						Type: "VALIDATE_STAGE", Category: "runtime", Level: level,
						Message:  st.Name + ": " + st.Detail + st.Error,
						Metadata: map[string]any{"stage": st.Name, "ok": st.OK},
						Bookmark: !st.OK, Tags: []string{"validate", st.Name},
					})
				}
			}
			ok := err == nil && res != nil && res.OK
			note := ""
			var failAt int64
			if res != nil && !res.OK {
				note = "validation stages failed"
				if ev, _ := sess.ListEvents(rr.Run.ID); ev != nil {
					for _, e := range ev {
						if e.Level == "error" {
							failAt = e.OffsetMS
							break
						}
					}
				}
			}
			if err != nil {
				note = err.Error()
			}
			recID := rr.finish(ctx, ok, note, failAt)
			if res != nil && recID != "" {
				res.RecordingID = recID
			}
		}
		payload := withNext(map[string]any{
			"result":  res,
			"warning": "NOT OBSERVED ≠ ABSENT",
		}, "apkcheck_lab_sessions_list", "apkcheck_lab_compare")
		if rr != nil {
			attachRunIDs(payload, rr, "")
			if res != nil && res.RecordingID != "" {
				payload["recording_id"] = res.RecordingID
			}
			payload["next"] = []string{"apkcheck_lab_sessions_get", "apkcheck_lab_ui"}
		}
		if err != nil {
			payload["error"] = err.Error()
			return jsonErrPayload(payload)
		}
		return jsonOK(payload)

	case "apkcheck_lab_sessions_list":
		_, _, _, sess, _, err := openLabSession(ws)
		if err != nil {
			return "", true, err
		}
		list, err := sess.List()
		if err != nil {
			return "", true, err
		}
		if list == nil {
			list = []*session.Run{}
		}
		return jsonOK(withNext(map[string]any{"sessions": list, "count": len(list)}, "apkcheck_lab_sessions_get", "apkcheck_lab_recordings_list"))

	case "apkcheck_lab_sessions_get":
		runID := firstNonEmpty(strArg(args, "run_id", ""), strArg(args, "id", ""), strArg(args, "session_id", ""))
		if runID == "" {
			return "", true, fmt.Errorf("run_id required")
		}
		_, _, _, sess, recMgr, err := openLabSession(ws)
		if err != nil {
			return "", true, err
		}
		run, err := sess.Get(runID)
		if err != nil {
			return "", true, err
		}
		ev, _ := sess.ListEvents(runID)
		var rec any
		if run.RecordingID != "" {
			rec, _ = recMgr.Get(run.RecordingID)
		}
		return jsonOK(withNext(map[string]any{
			"run": run, "events": ev, "recording": rec,
			"ui": "apkcheck lab ui → Runs tab",
		}, "apkcheck_lab_sessions_bookmark", "apkcheck_lab_ui"))

	case "apkcheck_lab_sessions_event":
		runID := firstNonEmpty(strArg(args, "run_id", ""), strArg(args, "id", ""))
		if runID == "" {
			return "", true, fmt.Errorf("run_id required")
		}
		_, _, _, sess, _, err := openLabSession(ws)
		if err != nil {
			return "", true, err
		}
		ev, err := sess.AddEvent(runID, session.Event{
			Type:     strArg(args, "event_type", "MCP_TOOL_CALL"),
			Source:   strArg(args, "source", "mcp"),
			Category: strArg(args, "category", "mcp"),
			Message:  strArg(args, "message", ""),
			Level:    strArg(args, "level", "info"),
			Metadata: map[string]any{"tool": strArg(args, "tool", ""), "args": args["metadata"]},
		})
		if err != nil {
			return "", true, err
		}
		return jsonOK(withNext(map[string]any{"event": ev}, "apkcheck_lab_sessions_get"))

	case "apkcheck_lab_sessions_bookmark":
		runID := firstNonEmpty(strArg(args, "run_id", ""), strArg(args, "id", ""))
		if runID == "" {
			return "", true, fmt.Errorf("run_id required")
		}
		_, _, _, sess, _, err := openLabSession(ws)
		if err != nil {
			return "", true, err
		}
		tags := []string{}
		if raw, ok := args["tags"].([]any); ok {
			for _, t := range raw {
				if s, ok := t.(string); ok {
					tags = append(tags, s)
				}
			}
		}
		ev, err := sess.Bookmark(runID, strArg(args, "title", "Bookmark"), strArg(args, "description", ""), tags)
		if err != nil {
			return "", true, err
		}
		return jsonOK(map[string]any{"bookmark": ev})

	case "apkcheck_lab_sessions_import_logcat":
		runID := firstNonEmpty(strArg(args, "run_id", ""), strArg(args, "id", ""), strArg(args, "session_id", ""))
		if runID == "" {
			return "", true, fmt.Errorf("run_id required")
		}
		_, _, _, sess, _, err := openLabSession(ws)
		if err != nil {
			return "", true, err
		}
		run, err := sess.Get(runID)
		if err != nil {
			return "", true, err
		}
		serial := firstNonEmpty(strArg(args, "serial", ""), strArg(args, "device_id", ""), run.RuntimeSerial)
		if serial == "" {
			serial = security.DiscoverDefaultSerial(parent)
		}
		if serial == "" {
			return "", true, fmt.Errorf("serial required")
		}
		pkg := firstNonEmpty(strArg(args, "package", ""), run.Package)
		ctx, cancel := labCtx(parent, 2*time.Minute)
		defer cancel()
		adbPath, _ := runner.LookPath("", "adb")
		client := &adb.Client{Path: adbPath}
		n, err := logsync.Import(ctx, client, serial, sess, run, logsync.ImportOptions{Package: pkg})
		if err != nil {
			return "", true, err
		}
		return jsonOK(withNext(map[string]any{
			"ok": true, "imported": n, "run_id": runID, "package": pkg,
			"note": "Kernel + app logcat lines appended to timeline",
		}, "apkcheck_lab_sessions_get", "apkcheck_lab_sessions_import_proxy"))

	case "apkcheck_lab_sessions_import_proxy":
		runID := firstNonEmpty(strArg(args, "run_id", ""), strArg(args, "id", ""), strArg(args, "session_id", ""))
		if runID == "" {
			return "", true, fmt.Errorf("run_id required")
		}
		store, _, _, sess, _, err := openLabSession(ws)
		if err != nil {
			return "", true, err
		}
		run, err := sess.Get(runID)
		if err != nil {
			return "", true, err
		}
		pm := proxy.New(filepath.Join(store.Root, "proxy"), ":8080")
		n := proxysync.Import(pm.WorkDir, sess, run)
		return jsonOK(withNext(map[string]any{
			"ok": true, "imported": n, "run_id": runID,
			"note": "mitmproxy flows.jsonl → network timeline events",
		}, "apkcheck_lab_sessions_get", "apkcheck_lab_ui"))

	case "apkcheck_lab_auth_pending":
		store, _, bus, _, _, err := openLabSession(ws)
		if err != nil {
			return "", true, err
		}
		auth := authgate.New(store.Root, bus)
		runID := firstNonEmpty(strArg(args, "run_id", ""), strArg(args, "id", ""))
		list := auth.Pending()
		if runID != "" {
			list = auth.PendingFor(runID)
		}
		return jsonOK(map[string]any{
			"pending": list, "count": len(list),
			"note": "Fill phone/OTP via apkcheck_lab_auth_submit or Lab UI Auth panel",
			"next": []string{"apkcheck_lab_auth_submit", "apkcheck_lab_ui"},
		})

	case "apkcheck_lab_auth_submit":
		runID := firstNonEmpty(strArg(args, "run_id", ""), strArg(args, "id", ""))
		if runID == "" {
			return "", true, fmt.Errorf("run_id required")
		}
		kind := firstNonEmpty(strArg(args, "kind", ""), "")
		value := strArg(args, "value", "")
		if kind == "" && strArg(args, "phone", "") != "" {
			kind, value = "phone", strArg(args, "phone", "")
		}
		if kind == "" && strArg(args, "otp", "") != "" {
			kind, value = "otp", strArg(args, "otp", "")
		}
		store, _, bus, _, _, err := openLabSession(ws)
		if err != nil {
			return "", true, err
		}
		auth := authgate.New(store.Root, bus)
		p, err := auth.Submit(runID, authgate.NormalizeKind(kind), value)
		if err != nil {
			return "", true, err
		}
		return jsonOK(map[string]any{"ok": true, "prompt": p, "next": []string{"apkcheck_lab_auth_pending"}})

	case "apkcheck_lab_auth_cancel":
		runID := firstNonEmpty(strArg(args, "run_id", ""), strArg(args, "id", ""))
		kind := strArg(args, "kind", "")
		if runID == "" || kind == "" {
			return "", true, fmt.Errorf("run_id and kind required")
		}
		store, _, bus, _, _, err := openLabSession(ws)
		if err != nil {
			return "", true, err
		}
		auth := authgate.New(store.Root, bus)
		ok := auth.Cancel(runID, authgate.NormalizeKind(kind))
		return jsonOK(map[string]any{"ok": ok, "run_id": runID, "kind": kind, "next": []string{"apkcheck_lab_auth_pending"}})

	case "apkcheck_lab_recordings_list":
		_, _, _, _, recMgr, err := openLabSession(ws)
		if err != nil {
			return "", true, err
		}
		list, err := recMgr.List()
		if err != nil {
			return "", true, err
		}
		if list == nil {
			list = []*recording.Artifact{}
		}
		return jsonOK(withNext(map[string]any{"recordings": list, "count": len(list)}, "apkcheck_lab_sessions_get", "apkcheck_lab_ui"))

	case "apkcheck_lab_recordings_retention":
		_, _, _, sess, recMgr, err := openLabSession(ws)
		if err != nil {
			return "", true, err
		}
		policy := strArg(args, "policy", "")
		if policy != "" {
			cfg := recording.RetentionConfig{Policy: recording.ParseRetention(policy)}
			if err := recording.SaveRetention(recMgr.Root, cfg); err != nil {
				return "", true, err
			}
		}
		cfg := recording.LoadRetention(recMgr.Root)
		out := map[string]any{"policy": cfg.Policy, "description": recording.DescribeRetention(cfg.Policy)}
		if boolArg(args, "cleanup", false) {
			res, err := recMgr.Cleanup(sess)
			if err != nil {
				return "", true, err
			}
			out["cleanup"] = res
		}
		return jsonOK(out)

	case "apkcheck_lab_recordings_get":
		recID := firstNonEmpty(strArg(args, "recording_id", ""), strArg(args, "id", ""))
		if recID == "" {
			return "", true, fmt.Errorf("recording_id required")
		}
		_, _, _, _, recMgr, err := openLabSession(ws)
		if err != nil {
			return "", true, err
		}
		art, err := recMgr.Get(recID)
		if err != nil {
			return "", true, err
		}
		playable := recording.HasPlayableMedia(art)
		out := map[string]any{
			"recording": art,
			"playable":  playable,
			"media_url": recording.FileURLPath(recID),
			"ui":        "apkcheck lab ui → Runs tab to play video",
		}
		if !playable {
			out["warning"] = "no usable video yet — check recording.status/note; re-validate with record=true on a booted emulator"
			if art.Note != "" {
				out["warning"] = art.Note
			}
		}
		return jsonOK(withNext(out, "apkcheck_lab_sessions_get", "apkcheck_lab_ui"))
	case "apkcheck_lab_sessions_screenshot":
		runID := firstNonEmpty(strArg(args, "run_id", ""), strArg(args, "id", ""), strArg(args, "session_id", ""))
		if runID == "" {
			return "", true, fmt.Errorf("run_id required")
		}
		ctx, cancel := labCtx(parent, 2*time.Minute)
		defer cancel()
		_, _, _, sess, recMgr, err := openLabSession(ws)
		if err != nil {
			return "", true, err
		}
		run, err := sess.Get(runID)
		if err != nil {
			return "", true, err
		}
		serial := firstNonEmpty(strArg(args, "serial", ""), strArg(args, "device_id", ""), run.RuntimeSerial)
		if serial == "" {
			serial = security.DiscoverDefaultSerial(ctx)
		}
		if serial == "" {
			return "", true, fmt.Errorf("serial required for screenshot")
		}
		path, err := recMgr.CaptureScreenshot(ctx, run, serial, strArg(args, "name", ""))
		if err != nil {
			return "", true, err
		}
		return jsonOK(withNext(map[string]any{"path": path, "run_id": runID}, "apkcheck_lab_sessions_get"))

	case "apkcheck_lab_compare":
		leftID := firstNonEmpty(strArg(args, "left", ""), strArg(args, "left_id", ""))
		rightID := firstNonEmpty(strArg(args, "right", ""), strArg(args, "right_id", ""))
		if leftID == "" || rightID == "" {
			return "", true, fmt.Errorf("left and right artifact ids required")
		}
		store, _, _, err := openLabPipe(ws)
		if err != nil {
			return "", true, err
		}
		left, err := store.Get(leftID)
		if err != nil {
			return "", true, err
		}
		right, err := store.Get(rightID)
		if err != nil {
			return "", true, err
		}
		return jsonOK(compare.Artifacts(left, right))

	case "apkcheck_lab_runtime_list":
		ctx, cancel := labCtx(parent, 30*time.Second)
		defer cancel()
		st, err := (&runtimes.Manager{}).Snapshot(ctx)
		if err != nil {
			return "", true, err
		}
		return jsonOK(withNext(map[string]any{
			"runtimes": st,
			"hint":     "Prefer serial for stop; use avd name for start/restart (never '(unknown AVD)')",
		}, "apkcheck_lab_runtime_start", "apkcheck_lab_runtime_stop"))

	case "apkcheck_lab_runtime_start":
		avd := strArg(args, "avd", "Pixel_8_API_34")
		if avd == "(unknown AVD)" {
			return "", true, fmt.Errorf("invalid avd name %q — pick a real AVD from apkcheck_lab_runtime_list", avd)
		}
		to := time.Duration(intArg(args, "timeout_sec", 600)) * time.Second
		ctx, cancel := labCtx(parent, to+time.Minute)
		defer cancel()
		serial, err := (&runtimes.Manager{}).Start(ctx, avd, boolArg(args, "cold_boot", false), to)
		if err != nil {
			return "", true, err
		}
		return jsonOK(withNext(map[string]any{"ok": true, "avd": avd, "serial": serial}, "apkcheck_lab_validate"))

	case "apkcheck_lab_runtime_stop":
		mgr := &runtimes.Manager{}
		ctx, cancel := labCtx(parent, 2*time.Minute)
		defer cancel()
		if boolArg(args, "all", false) {
			stopped, err := mgr.StopAll(ctx)
			if stopped == nil {
				stopped = []string{}
			}
			payload := map[string]any{"ok": true, "stopped": stopped}
			if err != nil {
				payload["error"] = err.Error()
				return jsonErrPayload(payload)
			}
			return jsonOK(payload)
		}
		avd := strArg(args, "avd", "")
		if avd == "(unknown AVD)" {
			avd = ""
		}
		serial := firstNonEmpty(strArg(args, "serial", ""), strArg(args, "device_id", ""))
		if serial == "" && avd == "" {
			return "", true, fmt.Errorf("serial, avd, or all=true required")
		}
		if err := mgr.Stop(ctx, serial, avd); err != nil {
			return "", true, err
		}
		return jsonOK(map[string]any{"ok": true})

	case "apkcheck_lab_runtime_restart":
		avd := strArg(args, "avd", "Pixel_8_API_34")
		if avd == "" || avd == "(unknown AVD)" {
			return "", true, fmt.Errorf("valid avd name required")
		}
		to := time.Duration(intArg(args, "timeout_sec", 600)) * time.Second
		ctx, cancel := labCtx(parent, to+time.Minute)
		defer cancel()
		serial, err := (&runtimes.Manager{}).Restart(ctx, avd, boolArg(args, "cold_boot", false), to)
		if err != nil {
			return "", true, err
		}
		return jsonOK(map[string]any{"ok": true, "avd": avd, "serial": serial})

	case "apkcheck_lab_security_catalog":
		return jsonOK(map[string]any{
			"templates":  security.Catalog(),
			"presets":    security.Presets(),
			"categories": security.Categories(),
			"note":       "Observations are review candidates — not automatic vulnerability claims. Authorized testing only.",
			"next":       []string{"apkcheck_lab_security_run", "apkcheck_lab_security_preset", "apkcheck_lab_workflow action=security_quick"},
		})

	case "apkcheck_lab_security_run":
		tid := firstNonEmpty(strArg(args, "template_id", ""), strArg(args, "template", ""))
		aid := artID(args)
		if tid == "" || aid == "" {
			return "", true, fmt.Errorf("template_id and artifact_id required")
		}
		ctx, cancel := labCtx(parent, 30*time.Minute)
		defer cancel()
		store, _, bus, sess, recMgr, err := openLabSession(ws)
		if err != nil {
			return "", true, err
		}
		scen := &scenarios.Engine{Root: store.Root, Bus: bus}
		scen.EnsureBuiltins()
		eng := &security.Engine{Store: store, Sec: &security.Store{Root: store.Root, Bus: bus}, Bus: bus, Scenarios: scen}
		serial := security.ResolveDeviceSerial(ctx,
			firstNonEmpty(strArg(args, "serial", ""), strArg(args, "device_id", "")),
			firstNonEmpty(strArg(args, "emulator", ""), strArg(args, "avd", "")))
		var rr *runRec
		if boolArg(args, "record", false) {
			rr, serial = beginRunRecording(ctx, sess, recMgr, session.StartOptions{
				Kind: session.KindSecurity, ArtifactID: aid,
			}, serial, strArg(args, "profile", "high"), firstNonEmpty(strArg(args, "emulator", ""), strArg(args, "avd", "")))
			if rr != nil {
				rr.add(session.Event{
					Type: "SECURITY_STARTED", Category: "runtime",
					Message: "template=" + tid, Metadata: map[string]any{"template_id": tid},
				})
			}
		}
		rep, err := eng.Run(ctx, security.RunOptions{
			ArtifactID: aid, TemplateID: tid, Serial: serial,
			Package:  strArg(args, "package", ""),
			Duration: time.Duration(intArg(args, "duration_sec", 12)) * time.Second,
		})
		payload := withNext(map[string]any{"report": rep}, "apkcheck_lab_security_observations", "apkcheck_lab_security_export")
		if rr != nil {
			ok := err == nil
			note := ""
			if err != nil {
				note = err.Error()
			}
			if rep != nil {
				rr.add(session.Event{
					Type: "SECURITY_FINISHED", Category: "runtime",
					Message: tid, Metadata: map[string]any{"ok": ok},
				})
			}
			recID := rr.finish(ctx, ok, note, 0)
			attachRunIDs(payload, rr, recID)
			payload["next"] = []string{"apkcheck_lab_sessions_get", "apkcheck_lab_security_observations"}
		}
		if err != nil {
			payload["error"] = err.Error()
			return jsonErrPayload(payload)
		}
		return jsonOK(payload)

	case "apkcheck_lab_security_preset":
		pid := firstNonEmpty(strArg(args, "preset_id", ""), strArg(args, "preset", ""))
		aid := artID(args)
		if pid == "" || aid == "" {
			return "", true, fmt.Errorf("preset_id and artifact_id required")
		}
		ctx, cancel := labCtx(parent, 60*time.Minute)
		defer cancel()
		store, _, bus, sess, recMgr, err := openLabSession(ws)
		if err != nil {
			return "", true, err
		}
		scen := &scenarios.Engine{Root: store.Root, Bus: bus}
		scen.EnsureBuiltins()
		eng := &security.Engine{Store: store, Sec: &security.Store{Root: store.Root, Bus: bus}, Bus: bus, Scenarios: scen}
		serial := security.ResolveDeviceSerial(ctx,
			firstNonEmpty(strArg(args, "serial", ""), strArg(args, "device_id", "")),
			firstNonEmpty(strArg(args, "emulator", ""), strArg(args, "avd", "")))
		var rr *runRec
		if boolArg(args, "record", false) {
			rr, serial = beginRunRecording(ctx, sess, recMgr, session.StartOptions{
				Kind: session.KindSecurity, ArtifactID: aid,
			}, serial, strArg(args, "profile", "high"), firstNonEmpty(strArg(args, "emulator", ""), strArg(args, "avd", "")))
			if rr != nil {
				rr.add(session.Event{
					Type: "SECURITY_PRESET_STARTED", Category: "runtime",
					Message: "preset=" + pid, Metadata: map[string]any{"preset_id": pid},
				})
			}
		}
		reps, err := eng.RunPreset(ctx, pid, security.RunOptions{ArtifactID: aid, Serial: serial})
		payload := withNext(map[string]any{"reports": reps}, "apkcheck_lab_security_observations")
		if rr != nil {
			ok := err == nil
			note := ""
			if err != nil {
				note = err.Error()
			}
			recID := rr.finish(ctx, ok, note, 0)
			attachRunIDs(payload, rr, recID)
			payload["next"] = []string{"apkcheck_lab_sessions_get", "apkcheck_lab_security_observations"}
		}
		if err != nil {
			payload["error"] = err.Error()
			return jsonErrPayload(payload)
		}
		return jsonOK(payload)

	case "apkcheck_lab_security_manifest":
		aid := artID(args)
		if aid == "" {
			return "", true, fmt.Errorf("artifact_id (or id) required")
		}
		store, _, _, err := openLabPipe(ws)
		if err != nil {
			return "", true, err
		}
		art, err := store.Get(aid)
		if err != nil {
			return "", true, err
		}
		rev, err := security.ReviewManifest(art)
		if err != nil {
			return "", true, err
		}
		return jsonOK(withNext(map[string]any{"review": rev, "note": "Review notes ≠ confirmed vulns"}, "apkcheck_lab_security_run"))

	case "apkcheck_lab_security_observations":
		store, _, bus, err := openLabPipe(ws)
		if err != nil {
			return "", true, err
		}
		sec := &security.Store{Root: store.Root, Bus: bus}
		list, err := sec.ListObservations()
		if err != nil {
			return "", true, err
		}
		if list == nil {
			list = []*security.Observation{}
		}
		return jsonOK(map[string]any{
			"count":        len(list),
			"observations": list,
			"note":         "Severity informational|potential|needs_review — tester decides disclosure",
			"next":         []string{"apkcheck_lab_security_export"},
		})

	case "apkcheck_lab_security_export":
		oid := firstNonEmpty(strArg(args, "observation_id", ""), strArg(args, "id", ""))
		if oid == "" {
			return "", true, fmt.Errorf("observation_id required")
		}
		store, _, bus, err := openLabPipe(ws)
		if err != nil {
			return "", true, err
		}
		sec := &security.Store{Root: store.Root, Bus: bus}
		o, err := sec.GetObservation(oid)
		if err != nil {
			return "", true, err
		}
		format := security.ExportFormat(strArg(args, "format", "markdown"))
		if format == "" {
			format = security.ExportMD
		}
		ext := map[security.ExportFormat]string{
			security.ExportJSON: ".json", security.ExportMD: ".md",
			security.ExportHTML: ".html", security.ExportZIP: ".zip",
		}[format]
		outDir := filepath.Join(store.Root, "exports")
		_ = os.MkdirAll(outDir, 0o750)
		out := filepath.Join(outDir, oid+ext)
		if err := security.ExportObservation(o, format, out); err != nil {
			return "", true, err
		}
		return jsonOK(map[string]any{"path": out, "format": format})

	case "apkcheck_lab_security_harness":
		store, _, _, err := openLabPipe(ws)
		if err != nil {
			return "", true, err
		}
		action := strArg(args, "action", "status")
		force := boolArg(args, "force", false)
		ctx, cancel := labCtx(parent, 20*time.Minute)
		defer cancel()
		switch action {
		case "seed":
			if err := security.SeedHarnessProjectOpts(store.Root, "testdata/lab/harness", force); err != nil {
				return "", true, err
			}
		case "build":
			if err := security.SeedHarnessProjectOpts(store.Root, "testdata/lab/harness", true); err != nil {
				return "", true, err
			}
			note, err := security.EnsureHarness(ctx, store.Root, nil, "")
			payload := map[string]any{"status": security.HarnessStatus(store.Root), "note": note}
			if err != nil {
				payload["error"] = err.Error()
				return jsonErrPayload(payload)
			}
			return jsonOK(payload)
		}
		return jsonOK(security.HarnessStatus(store.Root))

	case "apkcheck_lab_scenarios_list":
		store, _, bus, err := openLabPipe(ws)
		if err != nil {
			return "", true, err
		}
		eng := &scenarios.Engine{Root: store.Root, Bus: bus}
		eng.EnsureBuiltins()
		list, err := eng.List()
		if err != nil {
			return "", true, err
		}
		if list == nil {
			list = []*scenarios.Definition{}
		}
		return jsonOK(map[string]any{"scenarios": list})

	case "apkcheck_lab_scenarios_run":
		sid := firstNonEmpty(strArg(args, "scenario_id", ""), strArg(args, "id", ""))
		pkg := strArg(args, "package", "")
		serial := firstNonEmpty(strArg(args, "serial", ""), strArg(args, "device_id", ""))
		if sid == "" || pkg == "" {
			return "", true, fmt.Errorf("scenario_id and package required")
		}
		if serial == "" {
			serial = security.DiscoverDefaultSerial(parent)
		}
		if serial == "" {
			return "", true, fmt.Errorf("serial required — start emulator via apkcheck_lab_runtime_start first")
		}
		ctx, cancel := labCtx(parent, 10*time.Minute)
		defer cancel()
		store, _, bus, sess, recMgr, err := openLabSession(ws)
		if err != nil {
			return "", true, err
		}
		eng := &scenarios.Engine{Root: store.Root, Bus: bus}
		eng.EnsureBuiltins()
		scenName := sid
		if def, gerr := eng.Get(sid); gerr == nil && def != nil && def.Name != "" {
			scenName = def.Name
		}
		wantRecord := boolArg(args, "record", false)
		profile := strArg(args, "profile", "high")
		auth := authgate.New(store.Root, bus)
		var rr *runRec
		if wantRecord {
			rr, serial = beginRunRecording(ctx, sess, recMgr, session.StartOptions{
				Kind: session.KindScenario, ArtifactID: artID(args), ScenarioID: sid, Package: pkg,
				Meta: map[string]string{"scenario_name": scenName, "title": scenName},
			}, serial, profile, "")
		} else {
			run, serr := sess.Start(session.StartOptions{
				Kind: session.KindScenario, ArtifactID: artID(args), ScenarioID: sid,
				RuntimeSerial: serial, Package: pkg, Record: false,
				Meta:       map[string]string{"scenario_name": scenName, "title": scenName},
				MCPSession: "mcp",
			})
			if serr == nil && run != nil {
				rr = &runRec{Run: run, Sess: sess, RecMgr: recMgr}
			}
		}
		adbPath, _ := runner.LookPath("", "adb")
		client := &adb.Client{Path: adbPath}
		if rr != nil {
			_ = logsync.Clear(ctx, client, serial)
			if wantRecord && rr.Rec != nil {
				logsync.WarmRecording(2 * time.Second)
				rr.add(session.Event{
					Type: "RECORDING_READY", Category: "runtime",
					Message: "screenrecord warm — scenario actions start now",
					Tags:    []string{"recording"},
				})
			}
			rr.add(session.Event{
				Type: "SCENARIO_STARTED", Category: "scenario",
				Message: scenName, Tags: []string{"scenario", "app"},
				Metadata: map[string]any{"package": pkg, "scenario_id": sid},
			})
		}
		runOpt := scenarios.RunOptions{
			Serial: serial, Package: pkg, Activity: strArg(args, "activity", ""),
			Auth: auth, Phone: strArg(args, "phone", ""), OTP: strArg(args, "otp", ""),
		}
		if rr != nil {
			runOpt.LabRunID = rr.Run.ID
			runOpt.Sessions = sess
		}
		res, err := eng.Run(ctx, sid, artID(args), runOpt)
		payload := map[string]any{"result": res, "scenario_name": scenName}
		if rr != nil {
			logN, _ := logsync.Import(ctx, client, serial, sess, rr.Run, logsync.ImportOptions{Package: pkg})
			pm := proxy.New(filepath.Join(store.Root, "proxy"), ":8080")
			mitmN := proxysync.Import(pm.WorkDir, sess, rr.Run)
			payload["timeline_logcat"] = logN
			payload["timeline_mitm"] = mitmN
			ok := err == nil && res != nil && res.OK
			note := ""
			if err != nil {
				note = err.Error()
			} else if !ok {
				note = "scenario steps failed"
			}
			recID := rr.finish(ctx, ok, note, 0)
			attachRunIDs(payload, rr, recID)
			// After recording saved: wipe + cold-boot fresh emulator (Lab host / KVM).
			wantFresh := wantRecord
			if _, okFresh := args["fresh_emulator"]; okFresh {
				wantFresh = boolArg(args, "fresh_emulator", true)
			}
			if wantFresh && strings.HasPrefix(serial, "emulator-") {
				avd := firstNonEmpty(strArg(args, "avd", ""), "Pixel_8_API_34")
				fctx, fcancel := labCtx(parent, 14*time.Minute)
				fsSerial, ferr := (&runtimes.Manager{Bus: bus}).FreshAfterRecording(fctx, avd, serial, 12*time.Minute)
				fcancel()
				if ferr != nil {
					payload["fresh_emulator_error"] = ferr.Error()
				} else {
					payload["fresh_serial"] = fsSerial
					rr.add(session.Event{
						Type: "RUNTIME_FRESH", Category: "runtime",
						Message: "fresh emulator after recording saved · " + fsSerial,
						Tags:    []string{"emulator", "fresh"},
					})
				}
			}
			payload["next"] = []string{"apkcheck_lab_sessions_get", "apkcheck_lab_sessions_import_logcat", "apkcheck_lab_ui"}
		}
		if err != nil {
			payload["error"] = err.Error()
			return jsonErrPayload(payload)
		}
		return jsonOK(payload)

	case "apkcheck_lab_events":
		// Each MCP call opens a fresh in-process bus, so bus.Recent() alone is
		// always empty. Bridge CLI/UI/MCP session timelines from disk instead.
		_, _, bus, sess, _, err := openLabSession(ws)
		if err != nil {
			return "", true, err
		}
		ev := mergeMCPEventFeed(bus.Recent(), sess.RecentFeed(12, 600))
		limit := intArg(args, "limit", 40)
		if limit > 0 && len(ev) > limit {
			ev = ev[len(ev)-limit:]
		}
		return jsonOK(map[string]any{
			"count":  len(ev),
			"events": ev,
			"note":   "Includes session timelines from disk (CLI/UI/MCP). Live UI stream: lab ui → Live Log.",
			"next":   []string{"apkcheck_lab_sessions_get", "apkcheck_lab_ui"},
		})

	case "apkcheck_lab_proxy_status":
		store, _, _, err := openLabPipe(ws)
		if err != nil {
			return "", true, err
		}
		pm := proxy.New(filepath.Join(store.Root, "proxy"), ":8080")
		return jsonOK(pm.Status())

	case "apkcheck_lab_proxy_start":
		store, _, _, err := openLabPipe(ws)
		if err != nil {
			return "", true, err
		}
		pm := proxy.New(filepath.Join(store.Root, "proxy"), ":8080")
		if err := pm.Start(context.Background()); err != nil {
			return "", true, err
		}
		return jsonOK(withNext(map[string]any{"status": pm.Status(), "warning": "Authorized testing only"}, "apkcheck_lab_proxy_stop"))

	case "apkcheck_lab_proxy_stop":
		store, _, _, err := openLabPipe(ws)
		if err != nil {
			return "", true, err
		}
		pm := proxy.New(filepath.Join(store.Root, "proxy"), ":8080")
		_ = pm.Stop()
		return jsonOK(pm.Status())

	case "apkcheck_lab_certs":
		store, _, _, err := openLabPipe(ws)
		if err != nil {
			return "", true, err
		}
		return jsonOK((&certs.Manager{Root: store.Root}).Status())

	case "apkcheck_lab_ui":
		return jsonOK(map[string]any{
			"cli":     "apkcheck lab ui  # local fallback only",
			"url":     "http://13.0.0.216:8787",
			"note":    "Primary Lab UI/API is on the tool laptop (mdc → 13.0.0.216). Emulator may stay on Mac — pass serial. Same engine as CLI/MCP.",
			"tabs":    []string{"Workspace", "Artifacts", "Devices", "Runs", "Security", "Manifest", "Findings", "Compare", "Scenarios", "Proxy", "Certificates", "Events"},
			"devices": "Devices tab: start/stop/restart/stop-all emulators",
			"runs":    "Runs tab: device recording + synchronized event timeline (§35)",
			"palette": "⌘K command palette",
			"mcp":     "Prefer apkcheck_lab_help → apkcheck_lab_workflow; validate with record=true",
		})

	// ── IOC Scanner ─────────────────────────────────────────────────────────
	case "apkcheck_lab_ioc_scan":
		store, _, _, err := openLabPipe(ws)
		if err != nil {
			return "", true, err
		}
		artifactID := firstNonEmpty(strArg(args, "artifact_id", ""), strArg(args, "id", ""))
		if artifactID == "" {
			return "", true, fmt.Errorf("artifact_id required")
		}
		arts := store.List()
		var scanRoot string
		for _, a := range arts {
			if a.ID != artifactID {
				continue
			}
			for _, b := range arts {
				if b.Kind == "project" && b.ParentID == a.ID {
					scanRoot = b.Path
					break
				}
			}
			if scanRoot == "" {
				scanRoot = filepath.Dir(a.Path)
			}
			break
		}
		if scanRoot == "" {
			return "", true, fmt.Errorf("artifact %s not found", artifactID)
		}
		res := iocscan.Scan(artifactID, scanRoot)
		return jsonOK(map[string]any{
			"artifact_id":   res.ArtifactID,
			"files_scanned": res.FilesScanned,
			"findings":      res.Findings,
			"summary":       res.Summary,
			"total":         len(res.Findings),
			"error":         res.Error,
		})

	// ── Frida ────────────────────────────────────────────────────────────────
	case "apkcheck_lab_frida_status":
		serial := strArg(args, "serial", "")
		mgr := &fridapkg.Manager{}
		st := mgr.Status(parent, serial)
		return jsonOK(st)

	case "apkcheck_lab_frida_push":
		serial := strArg(args, "serial", "")
		hostPath := strArg(args, "host_path", "")
		if hostPath == "" {
			return "", true, fmt.Errorf("host_path required — download frida-server from GitHub Releases")
		}
		mgr := &fridapkg.Manager{}
		if err := mgr.PushServer(parent, serial, hostPath); err != nil {
			return "", true, err
		}
		return jsonOK(withNext(map[string]any{"status": "pushed", "device_path": fridapkg.ServerRemotePath},
			"apkcheck_lab_frida_ssl_unpin", "apkcheck_lab_frida_method_trace"))

	case "apkcheck_lab_frida_ssl_unpin":
		mgr := &fridapkg.Manager{}
		evs, err := mgr.RunHook(parent, fridapkg.RunOptions{
			Serial:     strArg(args, "serial", ""),
			Package:    strArg(args, "package", ""),
			Hook:       fridapkg.HookSSLUnpin,
			TimeoutSec: intArg(args, "timeout_sec", 30),
		})
		if err != nil {
			return "", true, err
		}
		return jsonOK(map[string]any{
			"hook": "ssl_unpin", "events": evs, "count": len(evs),
			"note": "SSL pinning bypassed — capture traffic via mitmproxy on :8080",
		})

	case "apkcheck_lab_frida_method_trace":
		mgr := &fridapkg.Manager{}
		evs, err := mgr.RunHook(parent, fridapkg.RunOptions{
			Serial:        strArg(args, "serial", ""),
			Package:       strArg(args, "package", ""),
			Hook:          fridapkg.HookMethodTrace,
			MethodPattern: strArg(args, "pattern", "."),
			TimeoutSec:    intArg(args, "timeout_sec", 30),
		})
		if err != nil {
			return "", true, err
		}
		return jsonOK(map[string]any{"hook": "method_trace", "events": evs, "count": len(evs)})

	case "apkcheck_lab_frida_dex_loader":
		mgr := &fridapkg.Manager{}
		evs, err := mgr.RunHook(parent, fridapkg.RunOptions{
			Serial:     strArg(args, "serial", ""),
			Package:    strArg(args, "package", ""),
			Hook:       fridapkg.HookDexLoader,
			TimeoutSec: intArg(args, "timeout_sec", 30),
		})
		if err != nil {
			return "", true, err
		}
		return jsonOK(map[string]any{"hook": "dex_loader", "events": evs, "count": len(evs)})

	case "apkcheck_lab_frida_network_trace":
		mgr := &fridapkg.Manager{}
		evs, err := mgr.RunHook(parent, fridapkg.RunOptions{
			Serial:     strArg(args, "serial", ""),
			Package:    strArg(args, "package", ""),
			Hook:       fridapkg.HookNetworkTrace,
			TimeoutSec: intArg(args, "timeout_sec", 30),
		})
		if err != nil {
			return "", true, err
		}
		return jsonOK(map[string]any{"hook": "network_trace", "events": evs, "count": len(evs)})

	default:
		return "", true, fmt.Errorf("unknown lab tool %q — call apkcheck_lab_help", name)
	}
}

func (s *Server) labStatus(ws string) (string, bool, error) {
	store, _, bus, sess, recMgr, err := openLabSession(ws)
	if err != nil {
		return "", true, err
	}
	arts := store.List()
	if arts == nil {
		arts = []*lab.Artifact{}
	}
	byKind := map[string]int{}
	for _, a := range arts {
		byKind[string(a.Kind)]++
	}
	ctx, cancel := labCtx(context.Background(), 20*time.Second)
	defer cancel()
	rt, rtErr := (&runtimes.Manager{}).Snapshot(ctx)
	sec := &security.Store{Root: store.Root, Bus: bus}
	obs, _ := sec.ListObservations()
	if obs == nil {
		obs = []*security.Observation{}
	}
	runs, _ := sess.List()
	if runs == nil {
		runs = []*session.Run{}
	}
	recs, _ := recMgr.List()
	if recs == nil {
		recs = []*recording.Artifact{}
	}
	ret := recording.LoadRetention(store.Root)
	payload := map[string]any{
		"workspace":       store.Root,
		"artifacts":       len(arts),
		"by_kind":         byKind,
		"observations":    len(obs),
		"sessions":        len(runs),
		"recordings":      len(recs),
		"retention":       ret.Policy,
		"latest_original": latestByKind(store, lab.KindOriginalAPK),
		"latest_signed":   latestByKind(store, lab.KindSignedAPK),
		"runtimes":        rt,
		"rules": []string{
			"DEX/Smali = ground truth",
			"Rebuild ≠ runtime success",
			"Observations ≠ automatic vulns",
			"NOT OBSERVED ≠ ABSENT",
			"Authorized testing only",
			"Recording is a session component (§35)",
		},
		"next": []string{"apkcheck_lab_help", "apkcheck_lab_workflow", "apkcheck_lab_sessions_list"},
	}
	if rtErr != nil {
		payload["runtimes_error"] = rtErr.Error()
	}
	return jsonOK(payload)
}

func (s *Server) labWorkflow(parent context.Context, ws string, args map[string]any) (string, bool, error) {
	action := firstNonEmpty(strArg(args, "action", ""), strArg(args, "workflow", ""), "status")
	switch action {
	case "status", "help":
		if action == "help" {
			return jsonOK(labHelpPayload())
		}
		return s.labStatus(ws)

	case "ensure_runtime":
		ctx, cancel := labCtx(parent, 12*time.Minute)
		defer cancel()
		mgr := &runtimes.Manager{}
		st, err := mgr.Snapshot(ctx)
		if err != nil {
			return "", true, err
		}
		if st != nil && st.EmulatorsRunning > 0 {
			return jsonOK(withNext(map[string]any{"ok": true, "already_running": true, "runtimes": st}, "apkcheck_lab_validate"))
		}
		avd := strArg(args, "avd", "Pixel_8_API_34")
		serial, err := mgr.Start(ctx, avd, boolArg(args, "cold_boot", false), 10*time.Minute)
		if err != nil {
			return "", true, err
		}
		return jsonOK(withNext(map[string]any{"ok": true, "started": true, "avd": avd, "serial": serial}, "apkcheck_lab_validate"))

	case "workspace_reset", "fresh_start":
		opts := workspace.FreshRunReset()
		if boolArg(args, "keep_observations", false) {
			opts.Observations = false
		}
		removed, err := workspace.Reset(ws, opts)
		if err != nil {
			return "", true, err
		}
		eng := &scenarios.Engine{Root: ws}
		eng.EnsureBuiltins()
		return jsonOK(withNext(map[string]any{
			"ok": true, "removed": removed, "workspace": ws,
			"note": "Prior sessions/recordings/logs wiped. Scenarios re-seeded.",
		}, "apkcheck_lab_scenarios_run", "apkcheck_lab_workflow"))

	case "fresh_scenario_rerun":
		// Wipe evidence → ensure runtime → harness → run named scenario with recording.
		// No product defaults — caller must pass package (+ usually scenario_id).
		sid := firstNonEmpty(strArg(args, "scenario_id", ""), strArg(args, "id", ""), "app-bg-probe")
		pkg := firstNonEmpty(strArg(args, "package", ""), "")
		if pkg == "" {
			return "", true, fmt.Errorf("package required (any Android package, e.g. com.example.app) — no hardcoded default")
		}
		removed, err := workspace.Reset(ws, workspace.FreshRunReset())
		if err != nil {
			return "", true, err
		}
		eng := &scenarios.Engine{Root: ws}
		eng.EnsureBuiltins()
		// ensure runtime
		{
			ctx, cancel := labCtx(parent, 12*time.Minute)
			mgr := &runtimes.Manager{}
			st, _ := mgr.Snapshot(ctx)
			if st == nil || st.EmulatorsRunning == 0 {
				avd := strArg(args, "avd", "Pixel_8_API_34")
				if _, err := mgr.Start(ctx, avd, false, 10*time.Minute); err != nil {
					cancel()
					return "", true, fmt.Errorf("ensure runtime: %w", err)
				}
			}
			cancel()
		}
		_ = security.SeedHarnessProject(ws, "testdata/lab/harness")
		// delegate to scenarios_run with record=true
		args2 := map[string]any{}
		for k, v := range args {
			args2[k] = v
		}
		args2["scenario_id"] = sid
		args2["package"] = pkg
		args2["record"] = true
		if strArg(args2, "profile", "") == "" {
			args2["profile"] = "high"
		}
		out, handled, err := s.execLabTool(parent, "apkcheck_lab_scenarios_run", args2)
		if err != nil {
			return "", true, err
		}
		payload := map[string]any{"reset_removed": removed, "scenario_id": sid, "package": pkg, "workspace": ws}
		if handled {
			var inner map[string]any
			if json.Unmarshal([]byte(out), &inner) == nil {
				payload["run"] = inner
			} else {
				payload["run_raw"] = out
			}
		}
		return jsonOK(payload)

	case "import_rebuild", "import_rebuild_validate":
		path := apkPath(args)
		if path == "" {
			return "", true, fmt.Errorf("apk (or path) required for %s", action)
		}
		ctx, cancel := labCtx(parent, 60*time.Minute)
		defer cancel()
		_, pipe, _, sess, recMgr, err := openLabSession(ws)
		if err != nil {
			return "", true, err
		}
		orig, err := pipe.ImportAPK(path, strArg(args, "label", ""))
		if err != nil {
			return "", true, err
		}
		signed, err := pipe.RebuildFull(ctx, orig.ID)
		if err != nil {
			return jsonErrPayload(map[string]any{"error": err.Error(), "original": orig})
		}
		out := map[string]any{
			"original": orig,
			"signed":   signed,
			"warning":  "Rebuild ≠ runtime success",
			"next":     []string{"apkcheck_lab_validate", "apkcheck_lab_security_preset"},
		}
		if action == "import_rebuild_validate" {
			serial := firstNonEmpty(strArg(args, "device_id", ""), strArg(args, "serial", ""))
			opt := pipeline.ValidateOptions{
				EmulatorAVD:  strArg(args, "emulator", "Pixel_8_API_34"),
				DeviceSerial: serial,
				Duration:     time.Duration(intArg(args, "duration_sec", 12)) * time.Second,
			}
			if opt.DeviceSerial != "" {
				opt.EmulatorAVD = ""
			}
			var rr *runRec
			// Default record=true for the full agent recipe so evidence is always available.
			doRecord := true
			if _, ok := args["record"]; ok {
				doRecord = boolArg(args, "record", true)
			}
			if doRecord {
				rr, serial = beginRunRecording(ctx, sess, recMgr, session.StartOptions{
					Kind: session.KindValidate, ArtifactID: signed.ID,
				}, serial, strArg(args, "profile", "balanced"), strArg(args, "emulator", "Pixel_8_API_34"))
				if serial != "" {
					opt.DeviceSerial = serial
					opt.EmulatorAVD = ""
				}
			}
			res, verr := pipe.Validate(ctx, signed.ID, opt)
			out["validate"] = res
			if rr != nil {
				if res != nil {
					res.LabRunID = rr.Run.ID
					for _, st := range res.Stages {
						level := "info"
						if !st.OK {
							level = "error"
						}
						rr.add(session.Event{
							Type: "VALIDATE_STAGE", Category: "runtime", Level: level,
							Message:  st.Name + ": " + st.Detail + st.Error,
							Bookmark: !st.OK,
						})
					}
				}
				ok := verr == nil && res != nil && res.OK
				note := ""
				if verr != nil {
					note = verr.Error()
				} else if !ok {
					note = "validation stages failed"
				}
				recID := rr.finish(ctx, ok, note, 0)
				attachRunIDs(out, rr, recID)
				if res != nil && recID != "" {
					res.RecordingID = recID
				}
			}
			if verr != nil {
				out["error"] = verr.Error()
				return jsonErrPayload(out)
			}
			out["next"] = []string{"apkcheck_lab_sessions_get", "apkcheck_lab_compare", "apkcheck_lab_ui"}
		}
		return jsonOK(out)

	case "security_quick":
		aid := artID(args)
		if aid == "" {
			store, _, _, err := openLabPipe(ws)
			if err != nil {
				return "", true, err
			}
			if latest := latestByKind(store, lab.KindSignedAPK); latest != nil {
				aid = latest.ID
			} else if latest := latestByKind(store, lab.KindOriginalAPK); latest != nil {
				aid = latest.ID
			}
		}
		if aid == "" {
			return "", true, fmt.Errorf("artifact_id required (or import an APK first)")
		}
		ctx, cancel := labCtx(parent, 60*time.Minute)
		defer cancel()
		store, _, bus, sess, recMgr, err := openLabSession(ws)
		if err != nil {
			return "", true, err
		}
		eng := &security.Engine{Store: store, Sec: &security.Store{Root: store.Root, Bus: bus}, Bus: bus}
		serial := firstNonEmpty(strArg(args, "serial", ""), strArg(args, "device_id", ""))
		if serial == "" {
			serial = security.DiscoverDefaultSerial(ctx)
		}
		var rr *runRec
		if boolArg(args, "record", false) {
			rr, serial = beginRunRecording(ctx, sess, recMgr, session.StartOptions{
				Kind: session.KindSecurity, ArtifactID: aid,
			}, serial, strArg(args, "profile", "balanced"), "")
		}
		art, _ := store.Get(aid)
		var manifest any
		if art != nil {
			if rev, err := security.ReviewManifest(art); err == nil {
				manifest = rev
			}
		}
		reps, err := eng.RunPreset(ctx, "quick-android-security", security.RunOptions{ArtifactID: aid, Serial: serial})
		obs, _ := eng.Sec.ListObservations()
		if obs == nil {
			obs = []*security.Observation{}
		}
		payload := map[string]any{
			"artifact_id":  aid,
			"preset":       "quick-android-security",
			"manifest":     manifest,
			"reports":      reps,
			"observations": obs,
			"note":         "Observations ≠ automatic vulnerability claims. Authorized testing only.",
			"next":         []string{"apkcheck_lab_security_export"},
		}
		if rr != nil {
			ok := err == nil
			note := ""
			if err != nil {
				note = err.Error()
			}
			recID := rr.finish(ctx, ok, note, 0)
			attachRunIDs(payload, rr, recID)
			payload["next"] = []string{"apkcheck_lab_sessions_get", "apkcheck_lab_security_export", "apkcheck_lab_ui"}
		}
		if err != nil {
			payload["error"] = err.Error()
			return jsonErrPayload(payload)
		}
		return jsonOK(payload)

	default:
		return "", true, fmt.Errorf("unknown workflow action %q — use status|ensure_runtime|workspace_reset|fresh_scenario_rerun|import_rebuild|import_rebuild_validate|security_quick|help", action)
	}
}

func labHelpPayload() map[string]any {
	return map[string]any{
		"title": "APKCheck Lab MCP — agent playbook",
		"rules": []string{
			"DEX/Smali is ground truth",
			"Rebuild file exists ≠ runtime success",
			"Observations ≠ automatic vulnerabilities",
			"NOT OBSERVED ≠ ABSENT",
			"Authorized testing only",
			"Device recording binds to lab run_id + shared timeline (§35)",
		},
		"start_here": []map[string]string{
			{"tool": "apkcheck_lab_status", "why": "Workspace + runtimes + sessions/recordings counts"},
			{"tool": "apkcheck_lab_workflow", "why": "One-shot recipes (import_rebuild_validate records by default)"},
			{"tool": "apkcheck_doctor", "why": "Tool readiness before long runs"},
		},
		"recording": map[string]any{
			"summary": "Pass record=true (or use import_rebuild_validate / fresh_scenario_rerun). Screenrecord starts before the first scenario action (2s warm-up). Timeline auto-imports kernel/app logcat + mitmproxy flows.",
			"tools": []string{
				"apkcheck_lab_validate",
				"apkcheck_lab_security_run",
				"apkcheck_lab_security_preset",
				"apkcheck_lab_scenarios_run",
				"apkcheck_lab_workflow action=import_rebuild_validate|fresh_scenario_rerun|security_quick",
				"apkcheck_lab_sessions_list|get|event|bookmark|screenshot|import_logcat|import_proxy",
				"apkcheck_lab_recordings_list|get|retention",
			},
			"timeline_categories": []string{"scenario", "app", "kernel", "network", "mcp", "runtime"},
			"watch_video":         "apkcheck lab ui → Runs tab (filters: Kernel · App · Mitmproxy · Scenario)",
			"profiles":            []string{"low", "balanced", "high"},
		},
		"recipes": []map[string]any{
			{
				"name": "Rebuild, validate & record",
				"steps": []string{
					`apkcheck_lab_workflow { "action": "import_rebuild_validate", "apk": "/abs/path/app.apk" }`,
					"Returns lab_run_id + recording_id — then sessions_get or open Runs UI",
					`Opt-out: { "record": false }`,
				},
			},
			{
				"name": "Validate with device recording",
				"steps": []string{
					`apkcheck_lab_validate { "artifact_id": "<signed-id>", "record": true, "profile": "balanced" }`,
					"Then apkcheck_lab_sessions_get / apkcheck_lab_ui → Runs",
				},
			},
			{
				"name": "Security triage with recording",
				"steps": []string{
					`apkcheck_lab_security_run { "template_id": "exported-components", "artifact_id": "<id>", "record": true }`,
					`apkcheck_lab_workflow { "action": "security_quick", "artifact_id": "<id>", "record": true }`,
				},
			},
			{
				"name": "Scenario with recording",
				"steps": []string{
					`apkcheck_lab_scenarios_run { "scenario_id": "<id>", "package": "com.app", "serial": "emulator-5554", "record": true }`,
				},
			},
			{
				"name": "Manage emulators",
				"steps": []string{
					"apkcheck_lab_runtime_list",
					`apkcheck_lab_workflow { "action": "ensure_runtime" }`,
					`apkcheck_lab_runtime_stop { "all": true }`,
				},
			},
		},
		"aliases": map[string]string{
			"artifact_id":  "also accepts id",
			"apk":          "also accepts path (resolved to absolute)",
			"device_id":    "also accepts serial",
			"template_id":  "also accepts template",
			"preset_id":    "also accepts preset",
			"run_id":       "also accepts id / session_id",
			"recording_id": "also accepts id on recordings_get",
		},
		"ui": "Lab UI on tool laptop → http://13.0.0.216:8787 (Runs = recording + timeline). Deploy: mdc compose up -d lab",
	}
}

func labToolDefs() []map[string]any {
	ws := prop("string", "Lab workspace (default ./lab-data)")
	art := prop("string", "Artifact id (alias: id)")
	return []map[string]any{
		tool("apkcheck_lab_help", "START HERE — Lab MCP playbook, recipes, aliases, epistemic rules for agents.",
			schema(map[string]any{})),
		tool("apkcheck_lab_status", "One-shot Lab dashboard: artifacts, runtimes, observations, latest ids, rules.",
			schema(map[string]any{"workspace": ws})),
		tool("apkcheck_lab_workflow", "Powerful one-shot recipes. workspace_reset wipes prior runs/recordings. fresh_scenario_rerun resets then records a named scenario (video named after scenario).",
			schema(map[string]any{
				"action":       prop("string", "status|help|ensure_runtime|workspace_reset|fresh_scenario_rerun|import_rebuild|import_rebuild_validate|security_quick"),
				"apk":          prop("string", "APK path (import_* actions)"),
				"path":         prop("string", "Alias for apk"),
				"artifact_id":  art,
				"id":           prop("string", "Alias for artifact_id"),
				"emulator":     prop("string", "AVD name"),
				"avd":          prop("string", "AVD for ensure_runtime"),
				"serial":       prop("string", "Device/emulator serial"),
				"scenario_id":  prop("string", "Scenario id for fresh_scenario_rerun (default: app-bg-probe)"),
				"package":      prop("string", "Target package — required for scenario runs (no hardcoded default)"),
				"duration_sec": prop("integer", "Validate observe seconds"),
				"record":       prop("boolean", "Device recording (default true for import_rebuild_validate / fresh_scenario_rerun)"),
				"profile":      prop("string", "Recording profile low|balanced|high"),
				"workspace":    ws,
			})),
		tool("apkcheck_lab_import", "Import an APK into the Lab artifact store. Pass apk or path (absolute preferred).",
			schema(map[string]any{"apk": prop("string", "APK path"), "path": prop("string", "Alias for apk"), "label": prop("string", "Display label"), "workspace": ws})),
		tool("apkcheck_lab_list", "List Lab artifacts (original/project/unsigned/signed lineage).",
			schema(map[string]any{"workspace": ws})),
		tool("apkcheck_lab_decompile", "apktool decode → tracked project artifact. Pass artifact_id or id.",
			schema(map[string]any{"artifact_id": art, "id": prop("string", "Alias"), "workspace": ws})),
		tool("apkcheck_lab_rebuild", "Full decompile→build→sign. Rebuild ≠ runtime success — validate next. Pass artifact_id or id.",
			schema(map[string]any{"artifact_id": art, "id": prop("string", "Alias"), "workspace": ws})),
		tool("apkcheck_lab_build", "apktool build project → unsigned APK artifact.",
			schema(map[string]any{"artifact_id": art, "id": prop("string", "Alias"), "workspace": ws})),
		tool("apkcheck_lab_sign", "zipalign+apksigner unsigned → signed APK.",
			schema(map[string]any{"artifact_id": art, "id": prop("string", "Alias"), "workspace": ws})),
		tool("apkcheck_lab_validate", "Install/launch/smoke-validate on emulator or device. Set record=true for §35 device recording + timeline.",
			schema(map[string]any{
				"artifact_id":  art,
				"id":           prop("string", "Alias"),
				"emulator":     prop("string", "AVD name"),
				"device_id":    prop("string", "Physical serial"),
				"serial":       prop("string", "Alias for device_id"),
				"duration_sec": prop("integer", "Observe window seconds"),
				"record":       prop("boolean", "Start device screen recording bound to lab run"),
				"profile":      prop("string", "Recording profile: low|balanced|high"),
				"workspace":    ws,
			})),
		tool("apkcheck_lab_sessions_list", "List Lab test runs (session envelopes with recording/timeline ids).",
			schema(map[string]any{"workspace": ws})),
		tool("apkcheck_lab_sessions_get", "Get one test run + timeline events + recording metadata.",
			schema(map[string]any{
				"run_id":     prop("string", "Test run id"),
				"id":         prop("string", "Alias for run_id"),
				"session_id": prop("string", "Alias for run_id"),
				"workspace":  ws,
			})),
		tool("apkcheck_lab_sessions_event", "Append a timeline event (MCP/AI action) onto a run clock.",
			schema(map[string]any{
				"run_id":     prop("string", "Test run id"),
				"id":         prop("string", "Alias"),
				"event_type": prop("string", "e.g. MCP_TOOL_CALL"),
				"source":     prop("string", "mcp|ai-agent|scenario|…"),
				"category":   prop("string", "mcp|network|runtime|…"),
				"message":    prop("string", "Human summary"),
				"tool":       prop("string", "Tool name when source=mcp"),
				"level":      prop("string", "info|warn|error"),
				"workspace":  ws,
			})),
		tool("apkcheck_lab_sessions_bookmark", "Bookmark a moment on the run timeline (protected from auto-cleanup).",
			schema(map[string]any{
				"run_id":      prop("string", "Test run id"),
				"id":          prop("string", "Alias"),
				"title":       prop("string", "Bookmark title"),
				"description": prop("string", "Details"),
				"workspace":   ws,
			})),
		tool("apkcheck_lab_sessions_import_logcat", "Import Android logcat into a run timeline (kernel + app behavior categories).",
			schema(map[string]any{
				"run_id":    prop("string", "Lab run id"),
				"serial":    prop("string", "Device serial (default: run serial)"),
				"package":   prop("string", "App package for log classification"),
				"workspace": ws,
			})),
		tool("apkcheck_lab_sessions_import_proxy", "Import mitmproxy flows.jsonl into a run timeline (network category).",
			schema(map[string]any{
				"run_id":    prop("string", "Lab run id"),
				"workspace": ws,
			})),
		tool("apkcheck_lab_sessions_screenshot", "Capture a device screenshot linked to a run timeline.",
			schema(map[string]any{
				"run_id":    prop("string", "Test run id"),
				"id":        prop("string", "Alias"),
				"serial":    prop("string", "Optional serial override"),
				"name":      prop("string", "Optional filename"),
				"workspace": ws,
			})),
		tool("apkcheck_lab_recordings_list", "List device recording artifacts.",
			schema(map[string]any{"workspace": ws})),
		tool("apkcheck_lab_recordings_get", "Get recording metadata + media_url for UI playback.",
			schema(map[string]any{
				"recording_id": prop("string", "Recording id"),
				"id":           prop("string", "Alias"),
				"workspace":    ws,
			})),
		tool("apkcheck_lab_recordings_retention", "Get/set recording retention; optional cleanup.",
			schema(map[string]any{
				"policy":    prop("string", "everything|7d|30d|failed_only|saved_only"),
				"cleanup":   prop("boolean", "Apply cleanup now"),
				"workspace": ws,
			})),
		tool("apkcheck_lab_compare", "Compare two Lab artifacts (lineage metadata).",
			schemaReq(map[string]any{"left": prop("string", "Left artifact id"), "right": prop("string", "Right artifact id"), "workspace": ws}, "left", "right")),
		tool("apkcheck_lab_runtime_list", "List Android emulator/device instances (same as UI Devices tab).",
			schema(map[string]any{})),
		tool("apkcheck_lab_runtime_start", "Start an AVD emulator instance.",
			schema(map[string]any{
				"avd":         prop("string", "AVD name (default Pixel_8_API_34)"),
				"cold_boot":   prop("boolean", "Cold boot"),
				"timeout_sec": prop("integer", "Boot timeout seconds"),
			})),
		tool("apkcheck_lab_runtime_stop", "Stop one emulator (avd/serial) or all (all=true).",
			schema(map[string]any{
				"avd":    prop("string", "AVD name"),
				"serial": prop("string", "emulator-5554"),
				"all":    prop("boolean", "Stop all emulators"),
			})),
		tool("apkcheck_lab_runtime_restart", "Restart an AVD (stop then start).",
			schema(map[string]any{
				"avd":         prop("string", "AVD name"),
				"cold_boot":   prop("boolean", "Cold boot"),
				"timeout_sec": prop("integer", "Boot timeout seconds"),
			})),
		tool("apkcheck_lab_security_catalog", "List authorized security templates + presets (observations ≠ vulns).",
			schema(map[string]any{})),
		tool("apkcheck_lab_security_run", "Run one security template against a Lab artifact. Pass record=true for device recording + timeline.",
			schema(map[string]any{
				"template_id":  prop("string", "e.g. exported-components"),
				"template":     prop("string", "Alias for template_id"),
				"artifact_id":  art,
				"id":           prop("string", "Alias"),
				"serial":       prop("string", "Optional serial"),
				"device_id":    prop("string", "Alias for serial"),
				"emulator":     prop("string", "AVD name — resolved to serial when device offline flag unused"),
				"avd":          prop("string", "Alias for emulator"),
				"package":      prop("string", "Optional package override"),
				"duration_sec": prop("integer", "Background observe seconds"),
				"record":       prop("boolean", "Bind device recording to this security run"),
				"profile":      prop("string", "Recording profile low|balanced|high"),
				"workspace":    ws,
			})),
		tool("apkcheck_lab_security_preset", "Run a security preset (composes templates). Pass record=true for one continuous recording.",
			schema(map[string]any{
				"preset_id":   prop("string", "e.g. quick-android-security"),
				"preset":      prop("string", "Alias"),
				"artifact_id": art,
				"id":          prop("string", "Alias"),
				"serial":      prop("string", "Optional serial"),
				"device_id":   prop("string", "Alias for serial"),
				"emulator":    prop("string", "AVD name resolved to serial"),
				"avd":         prop("string", "Alias for emulator"),
				"record":      prop("boolean", "Bind device recording"),
				"profile":     prop("string", "Recording profile"),
				"workspace":   ws,
			})),
		tool("apkcheck_lab_security_manifest", "Manifest security review panel (notes, not auto-vulns).",
			schema(map[string]any{"artifact_id": art, "id": prop("string", "Alias"), "workspace": ws})),
		tool("apkcheck_lab_security_observations", "List Lab security observations / evidence checkpoints.",
			schema(map[string]any{"workspace": ws})),
		tool("apkcheck_lab_security_export", "Export observation evidence (markdown|json|html|zip).",
			schema(map[string]any{
				"observation_id": prop("string", "Observation id"),
				"format":         prop("string", "markdown|json|html|zip"),
				"workspace":      ws,
			})),
		tool("apkcheck_lab_security_harness", "Test harness status/seed/build. build force-refreshes scaffold (fixes aapt2 attribute errors).",
			schema(map[string]any{
				"action":    prop("string", "status|seed|build"),
				"force":     prop("boolean", "Re-copy scaffold on seed"),
				"workspace": ws,
			})),
		tool("apkcheck_lab_scenarios_list", "List saved Lab scenarios.",
			schema(map[string]any{"workspace": ws})),
		tool("apkcheck_lab_scenarios_run", "Run a saved scenario on device/emulator for any package. Timeline: scenario steps + logcat (kernel/app) + mitm. record=true starts screenrecord before first action. fresh_emulator (default true when record) wipe+cold-boots after save. Login: phone/otp args or auth_submit. Shell/tap strings may use {{package}}.",
			schema(map[string]any{
				"scenario_id":     prop("string", "Scenario id (app-login-otp, app-bg-probe, app-settings-stealth, or any saved scenario)"),
				"package":         prop("string", "Target Android package (required — no default)"),
				"serial":          prop("string", "Device/emulator serial"),
				"artifact_id":     art,
				"activity":        prop("string", "Optional activity"),
				"record":          prop("boolean", "Bind device recording (starts before first scenario step)"),
				"profile":         prop("string", "Recording profile"),
				"phone":           prop("string", "Prefill phone for login prompts (any app)"),
				"otp":             prop("string", "Prefill SMS OTP for login prompts"),
				"fresh_emulator":  prop("boolean", "After recording saved: wipe-data + cold-boot (default true when record)"),
				"avd":             prop("string", "AVD name for fresh boot (default Pixel_8_API_34)"),
				"workspace":       ws,
			})),
		tool("apkcheck_lab_auth_pending", "List pending interactive prompts (phone/OTP/choice) for any package waiting for Lab UI or auth_submit.",
			schema(map[string]any{
				"run_id":    prop("string", "Optional filter by lab run id"),
				"workspace": ws,
			})),
		tool("apkcheck_lab_auth_submit", "Submit phone/SMS OTP or a choice (Allow / Don't allow / Skip) for a pending scenario prompt (any package).",
			schema(map[string]any{
				"run_id":    prop("string", "Lab run id"),
				"kind":      prop("string", "phone|otp|pin|text|choice"),
				"value":     prop("string", "Field value or choice label (Allow, Don't allow, Skip, …)"),
				"phone":     prop("string", "Shorthand for kind=phone"),
				"otp":       prop("string", "Shorthand for kind=otp"),
				"workspace": ws,
			})),
		tool("apkcheck_lab_auth_cancel", "Cancel a pending auth prompt (phone/OTP/choice) so a stuck scenario can exit the wait.",
			schema(map[string]any{
				"run_id":    prop("string", "Lab run id"),
				"kind":      prop("string", "phone|otp|pin|text|choice"),
				"workspace": ws,
			})),
		tool("apkcheck_lab_events", "Recent Lab events from session timelines on disk (works across CLI/UI/MCP). Prefer lab ui Live Log for live SSE.",
			schema(map[string]any{"limit": prop("integer", "Max events (default 40)"), "workspace": ws})),
		tool("apkcheck_lab_proxy_status", "mitmproxy status via pid file (off by default; authorized only).",
			schema(map[string]any{"workspace": ws})),
		tool("apkcheck_lab_proxy_start", "Start mitmdump for authorized traffic capture.",
			schema(map[string]any{"workspace": ws})),
		tool("apkcheck_lab_proxy_stop", "Stop mitmdump.",
			schema(map[string]any{"workspace": ws})),
		tool("apkcheck_lab_certs", "Lab certificate/keystore status (never returns private keys).",
			schema(map[string]any{"workspace": ws})),
		tool("apkcheck_lab_ui", "How to open the React Lab UI — same engine as MCP/CLI.",
			schema(map[string]any{})),

		// IOC Scanner
		tool("apkcheck_lab_ioc_scan",
			"Static IOC scan of decompiled APK sources: finds hardcoded secrets, public IPs, URLs, base64 blobs, DexClassLoader, SSL bypass, C2 keywords, telephony leaks.",
			schema(map[string]any{
				"artifact_id": art,
				"id":          prop("string", "Alias for artifact_id"),
				"workspace":   ws,
			})),

		// Frida dynamic instrumentation
		tool("apkcheck_lab_frida_status",
			"Check whether frida CLI is installed on host and frida-server is on device/running.",
			schema(map[string]any{"serial": prop("string", "Device serial (optional)")})),
		tool("apkcheck_lab_frida_push",
			"Push a frida-server binary to /data/local/tmp/frida-server on the device. Download from: https://github.com/frida/frida/releases",
			schema(map[string]any{
				"host_path": prop("string", "Local path to frida-server binary"),
				"serial":    prop("string", "Device serial"),
			})),
		tool("apkcheck_lab_frida_ssl_unpin",
			"Bypass SSL certificate pinning on a running app via Frida. Combine with apkcheck_lab_proxy_start for full traffic capture. AUTHORIZED TESTING ONLY.",
			schema(map[string]any{
				"package":     prop("string", "Target app package name (e.g. com.example.app)"),
				"serial":      prop("string", "Device serial"),
				"timeout_sec": prop("integer", "Hook run timeout in seconds (default 30)"),
			})),
		tool("apkcheck_lab_frida_method_trace",
			"Hook all methods matching a name pattern and report call arguments and return values.",
			schema(map[string]any{
				"package":     prop("string", "Target app package"),
				"pattern":     prop("string", "Method name substring to match (default: all methods)"),
				"serial":      prop("string", "Device serial"),
				"timeout_sec": prop("integer", "Timeout in seconds"),
			})),
		tool("apkcheck_lab_frida_dex_loader",
			"Detect dynamic DEX class loading (DexClassLoader, InMemoryDexClassLoader, PathClassLoader) at runtime.",
			schema(map[string]any{
				"package":     prop("string", "Target app package"),
				"serial":      prop("string", "Device serial"),
				"timeout_sec": prop("integer", "Timeout in seconds"),
			})),
		tool("apkcheck_lab_frida_network_trace",
			"Intercept Socket, URL.openConnection, and OkHttp3 network calls to surface undocumented endpoints.",
			schema(map[string]any{
				"package":     prop("string", "Target app package"),
				"serial":      prop("string", "Device serial"),
				"timeout_sec": prop("integer", "Timeout in seconds"),
			})),
	}
}
