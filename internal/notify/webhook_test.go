package notify

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/theworker02/blind-botnet/v2/internal/catch"
)

func TestWebhookPosts(t *testing.T) {
	got := make(chan map[string]any, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		got <- m
		w.WriteHeader(204)
	}))
	defer srv.Close()

	wh := NewWebhook(srv.URL, "tok", slog.New(slog.NewTextHandler(io.Discard, nil)))
	wh.Handle(catch.Record{IP: "203.0.113.1", Source: "honeypot", Service: "http", Path: "/", Reason: "hit", CaughtAt: time.Now().UTC()})
	select {
	case m := <-got:
		if m["text"] == nil {
			t.Fatalf("missing text: %#v", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for webhook")
	}
}
