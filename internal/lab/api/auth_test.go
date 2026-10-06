package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/armin/apkcheck/internal/lab"
	"github.com/armin/apkcheck/internal/lab/api"
	"github.com/armin/apkcheck/internal/lab/authgate"
	"github.com/armin/apkcheck/internal/lab/events"
	"github.com/armin/apkcheck/internal/lab/pipeline"
)

func TestAuthPendingAndSubmit(t *testing.T) {
	root := t.TempDir()
	bus := events.NewBus(16)
	store, err := lab.OpenStore(root, bus)
	if err != nil {
		t.Fatal(err)
	}
	srv := &api.Server{
		Store: store,
		Pipe:  &pipeline.Pipeline{Store: store, Bus: bus},
		Bus:   bus,
		Auth:  authgate.New(root, bus),
	}
	// Seed a pending prompt via Submit-before-wait pattern is empty; write pending via Wait in goroutine.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = srv.Auth.Wait(t.Context(), "run-auth-1", authgate.KindPhone, "Phone", "com.example.app", 0)
	}()
	// Let Wait create the pending file.
	for i := 0; i < 40; i++ {
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/auth/pending", nil))
		var body map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &body)
		if n, _ := body["count"].(float64); n >= 1 {
			break
		}
	}

	payload, _ := json.Marshal(map[string]any{"run_id": "run-auth-1", "phone": "09120001122"})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/submit", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("submit %d %s", rr.Code, rr.Body.String())
	}
	<-done
}
