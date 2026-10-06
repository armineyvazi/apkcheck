package mcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/armin/apkcheck/internal/mcp"
)

func TestMCPInitializeAndToolsList(t *testing.T) {
	in := bytes.NewBuffer(nil)
	writeRPC(in, 1, "initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "test", "version": "0"},
	})
	writeRPC(in, 2, "tools/list", map[string]any{})

	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := mcp.New(in, &out, &bytes.Buffer{}).Run(ctx); err != nil && err != context.DeadlineExceeded {
		// EOF ends Run cleanly
		if !strings.Contains(err.Error(), "EOF") {
			t.Fatalf("run: %v", err)
		}
	}

	dec := json.NewDecoder(&out)
	var initResp map[string]any
	if err := dec.Decode(&initResp); err != nil {
		t.Fatalf("decode init: %v\nout=%s", err, out.String())
	}
	result, _ := initResp["result"].(map[string]any)
	if result["protocolVersion"] == nil {
		t.Fatalf("init: %#v", initResp)
	}

	var toolsResp map[string]any
	if err := dec.Decode(&toolsResp); err != nil {
		t.Fatalf("decode tools: %v", err)
	}
	tr, _ := toolsResp["result"].(map[string]any)
	tools, _ := tr["tools"].([]any)
	if len(tools) < 5 {
		t.Fatalf("expected tools, got %#v", toolsResp)
	}
	names := map[string]bool{}
	for _, raw := range tools {
		m, _ := raw.(map[string]any)
		names[m["name"].(string)] = true
	}
	for _, want := range []string{
		"apkcheck_doctor", "apkcheck_analyze_ai", "apkcheck_principles",
		"apkcheck_lab_help", "apkcheck_lab_status", "apkcheck_lab_workflow",
		"apkcheck_lab_import", "apkcheck_lab_runtime_list", "apkcheck_lab_runtime_start",
		"apkcheck_lab_runtime_stop", "apkcheck_lab_security_catalog", "apkcheck_lab_ui",
		"apkcheck_lab_scenarios_run", "apkcheck_lab_proxy_start",
		"apkcheck_lab_sessions_list", "apkcheck_lab_sessions_get", "apkcheck_lab_recordings_list",
		"apkcheck_lab_recordings_retention", "apkcheck_lab_sessions_event", "apkcheck_lab_sessions_bookmark",
		"apkcheck_lab_sessions_import_logcat", "apkcheck_lab_sessions_import_proxy",
		"apkcheck_lab_auth_pending", "apkcheck_lab_auth_submit",
		"apkcheck_lab_sessions_screenshot", "apkcheck_lab_recordings_get",
	} {
		if !names[want] {
			t.Fatalf("missing tool %s (have %d tools)", want, len(names))
		}
	}
}

func TestMCPLabHelpAndStatus(t *testing.T) {
	in := bytes.NewBuffer(nil)
	writeRPC(in, 1, "tools/call", map[string]any{
		"name":      "apkcheck_lab_help",
		"arguments": map[string]any{},
	})
	writeRPC(in, 2, "tools/call", map[string]any{
		"name":      "apkcheck_lab_workflow",
		"arguments": map[string]any{"action": "help"},
	})
	var out bytes.Buffer
	_ = mcp.New(in, &out, &bytes.Buffer{}).Run(context.Background())
	dec := json.NewDecoder(&out)
	for i := 0; i < 2; i++ {
		var resp map[string]any
		if err := dec.Decode(&resp); err != nil {
			t.Fatalf("resp %d: %v", i, err)
		}
		result, _ := resp["result"].(map[string]any)
		if result["isError"] == true {
			t.Fatalf("unexpected error %#v", resp)
		}
		content, _ := result["content"].([]any)
		text := content[0].(map[string]any)["text"].(string)
		if !strings.Contains(text, "playbook") && !strings.Contains(text, "recipes") {
			t.Fatalf("help text missing recipes: %s", text[:min(200, len(text))])
		}
		if !strings.Contains(text, "recording") {
			t.Fatalf("help text missing recording section: %s", text[:min(300, len(text))])
		}
	}
}

func TestMCPLabStatusTool(t *testing.T) {
	dir := t.TempDir()
	in := bytes.NewBuffer(nil)
	writeRPC(in, 1, "tools/call", map[string]any{
		"name":      "apkcheck_lab_status",
		"arguments": map[string]any{"workspace": dir},
	})
	var out bytes.Buffer
	_ = mcp.New(in, &out, &bytes.Buffer{}).Run(context.Background())
	var resp map[string]any
	if err := json.NewDecoder(&out).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	result, _ := resp["result"].(map[string]any)
	content, _ := result["content"].([]any)
	text := content[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "workspace") || !strings.Contains(text, "rules") {
		t.Fatalf("status=%s", text)
	}
}

func TestMCPLabUITool(t *testing.T) {
	in := bytes.NewBuffer(nil)
	writeRPC(in, 1, "tools/call", map[string]any{
		"name":      "apkcheck_lab_ui",
		"arguments": map[string]any{},
	})
	var out bytes.Buffer
	_ = mcp.New(in, &out, &bytes.Buffer{}).Run(context.Background())
	var resp map[string]any
	if err := json.NewDecoder(&out).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	result, _ := resp["result"].(map[string]any)
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("%#v", resp)
	}
	text := content[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "Devices") || !strings.Contains(text, "lab ui") {
		t.Fatalf("text=%s", text)
	}
	if !strings.Contains(text, "Runs") {
		t.Fatalf("expected Runs tab in ui tool: %s", text)
	}
}

func TestMCPPrinciplesTool(t *testing.T) {
	in := bytes.NewBuffer(nil)
	writeRPC(in, 1, "tools/call", map[string]any{
		"name":      "apkcheck_principles",
		"arguments": map[string]any{},
	})
	var out bytes.Buffer
	_ = mcp.New(in, &out, &bytes.Buffer{}).Run(context.Background())
	var resp map[string]any
	if err := json.NewDecoder(&out).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	result, _ := resp["result"].(map[string]any)
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("%#v", resp)
	}
	text := content[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "DEX/Smali") {
		t.Fatalf("text=%s", text)
	}
}

func writeRPC(buf *bytes.Buffer, id int, method string, params any) {
	msg := map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}
	_ = json.NewEncoder(buf).Encode(msg)
}
