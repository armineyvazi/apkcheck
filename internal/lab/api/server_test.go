package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/armin/apkcheck/internal/lab"
	"github.com/armin/apkcheck/internal/lab/api"
	"github.com/armin/apkcheck/internal/lab/events"
	"github.com/armin/apkcheck/internal/lab/pipeline"
	"github.com/armin/apkcheck/internal/lab/session"
)

func newMinServer(t *testing.T) *api.Server {
	t.Helper()
	root := t.TempDir()
	bus := events.NewBus(20)
	store, err := lab.OpenStore(root, bus)
	if err != nil {
		t.Fatal(err)
	}
	return &api.Server{Store: store, Pipe: &pipeline.Pipeline{Store: store, Bus: bus}, Bus: bus}
}

func TestAPIUnknownEndpointJSON(t *testing.T) {
	root := t.TempDir()
	bus := events.NewBus(50)
	store, err := lab.OpenStore(root, bus)
	if err != nil {
		t.Fatal(err)
	}
	srv := &api.Server{Store: store, Pipe: &pipeline.Pipeline{Store: store, Bus: bus}, Bus: bus}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/does-not-exist", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 404 {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	ct := rr.Header().Get("Content-Type")
	if ct == "" || ct[:16] != "application/json" {
		t.Fatalf("content-type=%q", ct)
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("must be JSON not plain text: %v body=%q", err, rr.Body.String())
	}
	if body["error"] == "" {
		t.Fatalf("%#v", body)
	}
}

func TestAPIRuntimesJSON(t *testing.T) {
	root := t.TempDir()
	bus := events.NewBus(50)
	store, err := lab.OpenStore(root, bus)
	if err != nil {
		t.Fatal(err)
	}
	srv := &api.Server{Store: store, Pipe: &pipeline.Pipeline{Store: store, Bus: bus}, Bus: bus}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/runtimes", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("json: %v body=%q", err, rr.Body.String())
	}
}

func TestAPIEventsIncludesSessionTimeline(t *testing.T) {
	root := t.TempDir()
	bus := events.NewBus(50)
	store, err := lab.OpenStore(root, bus)
	if err != nil {
		t.Fatal(err)
	}
	sess := session.NewManager(root, nil) // nil bus = CLI-like writer
	run, err := sess.Start(session.StartOptions{Kind: session.KindValidate, ArtifactID: "apk-x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sess.AddEvent(run.ID, session.Event{Type: "LAUNCH", Message: "app up", Source: "system"}); err != nil {
		t.Fatal(err)
	}
	srv := &api.Server{Store: store, Pipe: &pipeline.Pipeline{Store: store, Bus: bus}, Bus: bus, Sessions: session.NewManager(root, bus)}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/events", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var list []events.Event
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range list {
		if e.Type == "LAUNCH" && e.Message == "app up" {
			found = true
		}
	}
	if !found {
		t.Fatalf("session timeline missing from /api/events: %s", rr.Body.String())
	}
}

func TestAPIEventStreamKeepalive(t *testing.T) {
	root := t.TempDir()
	bus := events.NewBus(50)
	store, err := lab.OpenStore(root, bus)
	if err != nil {
		t.Fatal(err)
	}
	srv := &api.Server{Store: store, Pipe: &pipeline.Pipeline{Store: store, Bus: bus}, Bus: bus}
	rr := httptest.NewRecorder()
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/api/events/stream", nil).WithContext(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.Handler().ServeHTTP(rr, req)
	}()
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stream handler did not exit")
	}
	body := rr.Body.String()
	if !strings.Contains(body, ": connected") {
		t.Fatalf("expected SSE connected comment, got %q", body)
	}
}

func TestAPIObservationsEmptyArray(t *testing.T) {
	root := t.TempDir()
	bus := events.NewBus(50)
	store, err := lab.OpenStore(root, bus)
	if err != nil {
		t.Fatal(err)
	}
	srv := &api.Server{Store: store, Pipe: &pipeline.Pipeline{Store: store, Bus: bus}, Bus: bus}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/security/observations", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Body.String() == "null\n" {
		t.Fatal("observations must not be bare null")
	}
	var list []any
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
}

func TestAPIHealthOK(t *testing.T) {
	srv := newMinServer(t)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if rr.Code != 200 {
		t.Fatalf("status=%d", rr.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["ok"] != true {
		t.Fatalf("want ok=true got %v", body)
	}
}

func TestAPIArtifactsReturnsArray(t *testing.T) {
	srv := newMinServer(t)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/artifacts", nil))
	if rr.Code != 200 {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := strings.TrimSpace(rr.Body.String())
	if !strings.HasPrefix(body, "[") {
		t.Fatalf("want JSON array got %q", body)
	}
}

func TestAPISecurityCatalogAndPresets(t *testing.T) {
	srv := newMinServer(t)
	for _, path := range []string{"/api/security/catalog", "/api/security/presets", "/api/security/categories"} {
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != 200 {
			t.Fatalf("%s status=%d body=%s", path, rr.Code, rr.Body.String())
		}
		if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Fatalf("%s content-type=%q", path, ct)
		}
	}
}

func TestAPISessionByIDNotFound(t *testing.T) {
	srv := newMinServer(t)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/sessions/no-such-run", nil))
	if rr.Code != 404 {
		t.Fatalf("want 404 got %d body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("want JSON error: %v", err)
	}
	if body["error"] == "" {
		t.Fatal("missing error field")
	}
}

func TestAPICORSPreflight(t *testing.T) {
	srv := newMinServer(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodOptions, "/api/health", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 204 {
		t.Fatalf("OPTIONS want 204 got %d", rr.Code)
	}
	if rr.Header().Get("Access-Control-Allow-Origin") == "" {
		t.Fatal("missing CORS header")
	}
}

func TestAPIArtifactByIDNotFound(t *testing.T) {
	srv := newMinServer(t)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/artifacts/does-not-exist", nil))
	if rr.Code != 404 {
		t.Fatalf("want 404 got %d body=%s", rr.Code, rr.Body.String())
	}
}
