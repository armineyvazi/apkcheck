// Package mcp implements a minimal Model Context Protocol (stdio) server for apkcheck.
//
// Designed for Cursor / Claude / other MCP clients so agents can call doctor,
// analyze, devices, emulators, and AI digests without shell scraping.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/armin/apkcheck/internal/analyze"
	"github.com/armin/apkcheck/internal/decompiler"
	"github.com/armin/apkcheck/internal/doctor"
	aireport "github.com/armin/apkcheck/internal/report/ai"
	appruntime "github.com/armin/apkcheck/internal/runtime"
	"github.com/armin/apkcheck/pkg/model"
)

const protocolVersion = "2024-11-05"

// Server speaks MCP JSON-RPC over stdin/stdout.
type Server struct {
	in  io.Reader
	out io.Writer
	err io.Writer
}

func New(in io.Reader, out, err io.Writer) *Server {
	if err == nil {
		err = io.Discard
	}
	return &Server{in: in, out: out, err: err}
}

// Run processes MCP messages until EOF.
func (s *Server) Run(ctx context.Context) error {
	dec := json.NewDecoder(s.in)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		var raw map[string]json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		var id any
		if v, ok := raw["id"]; ok {
			_ = json.Unmarshal(v, &id)
		}
		var method string
		_ = json.Unmarshal(raw["method"], &method)
		if method == "" {
			continue
		}
		// Notifications have no id response.
		if _, hasID := raw["id"]; !hasID {
			continue
		}
		var params json.RawMessage
		if v, ok := raw["params"]; ok {
			params = v
		}
		result, callErr := s.dispatch(ctx, method, params)
		if callErr != nil {
			s.writeError(id, -32000, callErr.Error())
			continue
		}
		s.writeResult(id, result)
	}
}

func (s *Server) dispatch(ctx context.Context, method string, params json.RawMessage) (any, error) {
	switch method {
	case "initialize":
		return map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
			"serverInfo": map[string]any{
				"name":    "apkcheck",
				"version": analyze.Version,
			},
			"instructions": "APKCheck Lab MCP for AI agents. START: apkcheck_lab_help then apkcheck_lab_status. Prefer apkcheck_lab_workflow (import_rebuild_validate records by default). Pass record=true on validate/security/scenarios. Sessions: sessions_list|get|event|bookmark|screenshot. Recordings: recordings_list|get|retention. Watch video in lab ui → Runs. Aliases: id↔artifact_id, path↔apk, serial↔device_id, run_id↔session_id. DEX/Smali=truth. Rebuild≠runtime success. Observations≠vulns. NOT OBSERVED≠ABSENT. Authorized testing only.",
		}, nil
	case "ping":
		return map[string]any{"ok": true}, nil
	case "tools/list":
		return map[string]any{"tools": toolDefs()}, nil
	case "tools/call":
		return s.callTool(ctx, params)
	default:
		return nil, fmt.Errorf("method not found: %s", method)
	}
}

type toolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

func (s *Server) callTool(ctx context.Context, params json.RawMessage) (any, error) {
	var p toolCallParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	text, isErr, err := s.execTool(ctx, p.Name, p.Arguments)
	if err != nil {
		return toolResult(err.Error(), true), nil
	}
	return toolResult(text, isErr), nil
}

func toolResult(text string, isError bool) map[string]any {
	return map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": text},
		},
		"isError": isError,
	}
}

func (s *Server) execTool(ctx context.Context, name string, args map[string]any) (string, bool, error) {
	switch name {
	case "apkcheck_doctor":
		rep := doctor.Check(ctx, decompiler.Paths{})
		b, _ := json.MarshalIndent(map[string]any{
			"ok":      rep.OK,
			"tools":   rep.Tools,
			"version": analyze.Version,
			"hint":    "FernFlower may need Java 25+ even when PATH java is 17",
		}, "", "  ")
		return string(b), !rep.OK, nil

	case "apkcheck_devices":
		devs, err := appruntime.ListDevices(ctx)
		if err != nil {
			return "", true, err
		}
		b, _ := json.MarshalIndent(devs, "", "  ")
		return string(b), false, nil

	case "apkcheck_emulators":
		avds, err := appruntime.ListEmulators(ctx)
		if err != nil {
			return "", true, err
		}
		b, _ := json.MarshalIndent(map[string]any{
			"avds": avds,
			"hint": "If empty: apkcheck_emulator_create with name Pixel_8_API_34",
		}, "", "  ")
		return string(b), false, nil

	case "apkcheck_emulator_create":
		opt := appruntime.EmulatorCreateOptions{
			Name:     strArg(args, "name", "Pixel_8_API_34"),
			API:      strArg(args, "api", "34"),
			Tag:      strArg(args, "tag", "google_apis"),
			ABI:      strArg(args, "abi", "arm64-v8a"),
			Device:   strArg(args, "device", "pixel_8"),
			Force:    boolArg(args, "force", false),
			Progress: s.err,
		}
		if err := appruntime.CreateEmulator(ctx, opt); err != nil {
			return "", true, err
		}
		return fmt.Sprintf(`{"ok":true,"avd":%q,"next":"apkcheck_runtime with emulator=%s"}`, opt.Name, opt.Name), false, nil

	case "apkcheck_analyze_ai":
		apk := strArg(args, "apk", "")
		if apk == "" {
			return "", true, fmt.Errorf("apk path required")
		}
		outDir := strArg(args, "output", filepath.Join(os.TempDir(), "apkcheck-mcp"))
		limit := intArg(args, "limit", 500)
		focus := strArg(args, "focus", "")
		cfg := analyze.Config{
			APKPath: apk, OutputDir: outDir, Workers: 4, Limit: limit, Focus: focus,
			SkipFramework: true, SkipSynthetic: true, Timeout: 30 * time.Minute,
		}
		result, err := analyze.New(cfg).Analyze(ctx)
		if err != nil {
			return "", true, err
		}
		dig := aireport.FromResult(result, aireport.Options{})
		// Persist digest for follow-up tools.
		_ = os.MkdirAll(outDir, 0o750)
		path := filepath.Join(outDir, "ai-digest.json")
		raw, _ := json.MarshalIndent(dig, "", "  ")
		_ = os.WriteFile(path, raw, 0o640)
		dig.Notes = append(dig.Notes, "wrote "+path)
		out, _ := json.MarshalIndent(dig, "", "  ")
		return string(out), false, nil

	case "apkcheck_digest_file":
		path := strArg(args, "report_json", "")
		if path == "" {
			return "", true, fmt.Errorf("report_json path required (analysis/report.json)")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", true, err
		}
		var result model.AnalysisResult
		if err := json.Unmarshal(data, &result); err != nil {
			return "", true, err
		}
		dig := aireport.FromResult(&result, aireport.Options{})
		out, _ := json.MarshalIndent(dig, "", "  ")
		return string(out), false, nil

	case "apkcheck_runtime":
		apk := strArg(args, "apk", "")
		if apk == "" {
			return "", true, fmt.Errorf("apk path required")
		}
		opts := appruntime.Options{
			APKPath:      apk,
			OutputDir:    strArg(args, "output", "./analysis"),
			Mode:         strArg(args, "mode", ""),
			DeviceSerial: strArg(args, "device_id", ""),
			EmulatorAVD:  strArg(args, "emulator", ""),
			Screenshots:  boolArg(args, "screenshots", false),
			KeepEmulator: boolArg(args, "keep_emulator", false),
		}
		if opts.Mode == "" {
			if opts.EmulatorAVD != "" {
				opts.Mode = "emulator"
			} else if opts.DeviceSerial != "" || boolArg(args, "device", false) {
				opts.Mode = "device"
			}
		}
		ev, err := appruntime.Run(ctx, opts)
		payload := map[string]any{}
		if ev != nil {
			payload["session_id"] = ev.SessionID
			payload["runtime"] = ev.Runtime
			payload["crashes"] = len(ev.Crashes)
			payload["permissions"] = len(ev.Permissions)
			payload["network"] = len(ev.Network)
			payload["timeline"] = len(ev.Timeline)
			payload["correlations"] = len(ev.Correlations)
			payload["logcat"] = ev.LogcatPath
			payload["notes"] = ev.Notes
			payload["limitations"] = ev.Limitations
			payload["warning"] = "NOT OBSERVED ≠ absent"
		}
		if err != nil {
			payload["error"] = err.Error()
			b, _ := json.MarshalIndent(payload, "", "  ")
			return string(b), true, nil
		}
		b, _ := json.MarshalIndent(payload, "", "  ")
		return string(b), false, nil

	case "apkcheck_principles":
		b, _ := json.MarshalIndent(map[string]any{
			"principles":   aireport.FromResult(nil, aireport.Options{}).Principles,
			"version":      analyze.Version,
			"core":         "DEX/Smali is ground truth; decompilers are reconstructions; runtime is partial observation",
			"not_observed": "NOT OBSERVED ≠ ABSENT",
		}, "", "  ")
		return string(b), false, nil

	case "apkcheck_hunt":
		apk := strArg(args, "apk", "")
		if apk == "" {
			return "", true, fmt.Errorf("apk path required")
		}
		outDir := strArg(args, "output", filepath.Join(os.TempDir(), "apkcheck-hunt"))
		limit := intArg(args, "limit", 800)
		cfg := analyze.Config{
			APKPath: apk, OutputDir: outDir, Workers: 4, Limit: limit, Focus: "security",
			SkipFramework: true, SkipSynthetic: true, Timeout: 30 * time.Minute,
		}
		result, err := analyze.New(cfg).Analyze(ctx)
		if err != nil {
			return "", true, err
		}
		_ = os.MkdirAll(outDir, 0o750)
		jp := filepath.Join(outDir, "report.json")
		raw, _ := json.MarshalIndent(result, "", "  ")
		_ = os.WriteFile(jp, raw, 0o640)
		summary := map[string]any{
			"version":       analyze.Version,
			"findings":      len(result.Findings),
			"disagreements": result.Summary.MethodsDisagreement,
			"secrets":       countCat(result.Findings, "hardcoded_secret"),
			"native":        len(result.Native),
			"jni":           len(result.JNI),
			"report_json":   jp,
			"note":          "Use apkcheck_findings / apkcheck_disagreements / apkcheck_evidence on report_json",
			"principles":    []string{"STATIC_EVIDENCE vs INFERENCE", "NOT OBSERVED ≠ ABSENT", "AI is not source of truth"},
		}
		b, _ := json.MarshalIndent(summary, "", "  ")
		return string(b), false, nil

	case "apkcheck_findings":
		result, err := loadReport(strArg(args, "report_json", ""))
		if err != nil {
			return "", true, err
		}
		classFilter := strArg(args, "evidence_class", "")
		var out []model.Finding
		for _, f := range result.Findings {
			if classFilter != "" && string(f.Class) != classFilter {
				continue
			}
			out = append(out, f)
		}
		b, _ := json.MarshalIndent(map[string]any{
			"count":    len(out),
			"findings": out,
			"note":     "INFERENCE is not a confirmed vulnerability",
		}, "", "  ")
		return string(b), false, nil

	case "apkcheck_disagreements":
		result, err := loadReport(strArg(args, "report_json", ""))
		if err != nil {
			return "", true, err
		}
		var out []model.MethodResult
		for _, m := range result.Methods {
			if m.Status == model.ConfidenceDisagreement {
				out = append(out, m)
			}
		}
		b, _ := json.MarshalIndent(map[string]any{"count": len(out), "methods": out}, "", "  ")
		return string(b), false, nil

	case "apkcheck_evidence":
		result, err := loadReport(strArg(args, "report_json", ""))
		if err != nil {
			return "", true, err
		}
		b, _ := json.MarshalIndent(map[string]any{
			"graph":           result.Graph,
			"jni":             result.JNI,
			"native":          result.Native,
			"semantic_sample": truncateSemantic(result.Semantic, 30),
			"runtime_obs":     result.RuntimeObs,
			"note":            "Navigate graph nodes; AI must cite evidence_class",
		}, "", "  ")
		return string(b), false, nil

	case "apkcheck_query_methods":
		result, err := loadReport(strArg(args, "report_json", ""))
		if err != nil {
			return "", true, err
		}
		q := strings.ToLower(strArg(args, "query", ""))
		tag := strArg(args, "tag", "")
		var out []model.MethodResult
		for _, m := range result.Methods {
			if tag != "" {
				ok := false
				for _, t := range m.SecurityTags {
					if t == tag {
						ok = true
						break
					}
				}
				if !ok {
					continue
				}
			}
			if q != "" {
				blob := strings.ToLower(m.Ref.Class + "." + m.Ref.Name + " " + m.Verdict)
				if !strings.Contains(blob, q) {
					continue
				}
			}
			out = append(out, m)
			if len(out) >= 50 {
				break
			}
		}
		b, _ := json.MarshalIndent(map[string]any{"count": len(out), "methods": out}, "", "  ")
		return string(b), false, nil

	default:
		if strings.HasPrefix(name, "apkcheck_lab_") {
			return s.execLabTool(ctx, name, args)
		}
		return "", true, fmt.Errorf("unknown tool %q", name)
	}
}

func loadReport(path string) (*model.AnalysisResult, error) {
	if path == "" {
		return nil, fmt.Errorf("report_json path required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var result model.AnalysisResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func countCat(fs []model.Finding, cat string) int {
	n := 0
	for _, f := range fs {
		if string(f.Category) == cat {
			n++
		}
	}
	return n
}

func truncateSemantic(in []model.SemanticAssessment, n int) []model.SemanticAssessment {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func toolDefs() []map[string]any {
	base := []map[string]any{
		tool("apkcheck_doctor", "Check Java/JADX/Apktool/CFR/FernFlower/ADB readiness. FernFlower may need Java 25+.",
			schema(map[string]any{})),
		tool("apkcheck_devices", "List physical Android devices connected via ADB/USB.",
			schema(map[string]any{})),
		tool("apkcheck_emulators", "List local macOS Android Virtual Devices.",
			schema(map[string]any{})),
		tool("apkcheck_emulator_create", "Download system image (CDN fallback) and create an AVD on macOS.",
			schema(map[string]any{
				"name":  prop("string", "AVD name (default Pixel_8_API_34)"),
				"api":   prop("string", "API level"),
				"tag":   prop("string", "google_apis|default"),
				"abi":   prop("string", "arm64-v8a"),
				"force": prop("boolean", "recreate if exists"),
			})),
		tool("apkcheck_analyze_ai", "Static APK analysis returning apkcheck.ai.v1 digest (best for agents).",
			schemaReq(map[string]any{
				"apk":    prop("string", "Absolute path to .apk"),
				"output": prop("string", "Output directory"),
				"limit":  prop("integer", "Max methods (default 500)"),
				"focus":  prop("string", "Optional: security"),
			}, "apk")),
		tool("apkcheck_digest_file", "Convert an existing report.json into an AI digest.",
			schemaReq(map[string]any{
				"report_json": prop("string", "Path to analysis/report.json"),
			}, "report_json")),
		tool("apkcheck_runtime", "Install/launch APK on device or emulator; returns runtime evidence summary.",
			schemaReq(map[string]any{
				"apk":           prop("string", "APK path"),
				"mode":          prop("string", "device|emulator"),
				"device_id":     prop("string", "Physical serial"),
				"device":        prop("boolean", "Prefer physical device"),
				"emulator":      prop("string", "AVD name"),
				"output":        prop("string", "Output dir"),
				"screenshots":   prop("boolean", "Capture screenshots"),
				"keep_emulator": prop("boolean", "Keep emulator running"),
			}, "apk")),
		tool("apkcheck_principles", "Return evidence principles agents must follow.",
			schema(map[string]any{})),
		tool("apkcheck_hunt", "Full first-pass hunt: static + findings + semantic + native/JNI + evidence graph.",
			schemaReq(map[string]any{
				"apk":    prop("string", "APK/XAPK/APKS/AAB path"),
				"output": prop("string", "Output directory"),
				"limit":  prop("integer", "Max methods (default 800)"),
			}, "apk")),
		tool("apkcheck_findings", "List security findings from report.json with evidence_class discipline.",
			schemaReq(map[string]any{
				"report_json":    prop("string", "Path to report.json"),
				"evidence_class": prop("string", "Optional filter: STATIC_EVIDENCE|INFERENCE|…"),
			}, "report_json")),
		tool("apkcheck_disagreements", "Methods where decompilers disagree vs Smali.",
			schemaReq(map[string]any{
				"report_json": prop("string", "Path to report.json"),
			}, "report_json")),
		tool("apkcheck_evidence", "Evidence graph + JNI + native + semantic sample.",
			schemaReq(map[string]any{
				"report_json": prop("string", "Path to report.json"),
			}, "report_json")),
		tool("apkcheck_query_methods", "Search methods by query string and/or security tag.",
			schemaReq(map[string]any{
				"report_json": prop("string", "Path to report.json"),
				"query":       prop("string", "Substring match on class/method/verdict"),
				"tag":         prop("string", "Security tag e.g. webview, auth, crypto"),
			}, "report_json")),
	}
	return append(base, labToolDefs()...)
}

func tool(name, desc string, inputSchema map[string]any) map[string]any {
	return map[string]any{
		"name":        name,
		"description": desc,
		"inputSchema": inputSchema,
	}
}

func schema(props map[string]any) map[string]any {
	return map[string]any{"type": "object", "properties": props}
}

func schemaReq(props map[string]any, required ...string) map[string]any {
	return map[string]any{"type": "object", "properties": props, "required": required}
}

func prop(typ, desc string) map[string]any {
	return map[string]any{"type": typ, "description": desc}
}

func (s *Server) writeResult(id any, result any) {
	_ = json.NewEncoder(s.out).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  result,
	})
}

func (s *Server) writeError(id any, code int, msg string) {
	_ = json.NewEncoder(s.out).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]any{
			"code":    code,
			"message": msg,
		},
	})
}

func strArg(args map[string]any, key, def string) string {
	if args == nil {
		return def
	}
	v, ok := args[key]
	if !ok || v == nil {
		return def
	}
	switch t := v.(type) {
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}

func boolArg(args map[string]any, key string, def bool) bool {
	if args == nil {
		return def
	}
	v, ok := args[key]
	if !ok || v == nil {
		return def
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true") || t == "1"
	default:
		return def
	}
}

func intArg(args map[string]any, key string, def int) int {
	if args == nil {
		return def
	}
	v, ok := args[key]
	if !ok || v == nil {
		return def
	}
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case json.Number:
		n, _ := t.Int64()
		return int(n)
	case string:
		var n int
		fmt.Sscanf(t, "%d", &n)
		if n != 0 {
			return n
		}
	}
	return def
}
