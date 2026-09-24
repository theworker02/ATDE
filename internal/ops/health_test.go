package ops

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthEndpoints(t *testing.T) {
	m := NewMetrics("0.1.0-test", "all")
	m.HoneypotHits.Add(3)
	h := &Handler{Metrics: m, Ready: func() bool { return true }}
	mux := http.NewServeMux()
	h.Mount(mux)

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "ok") {
		t.Fatalf("healthz: %d %s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "atde_honeypot_hits_total 3") {
		t.Fatalf("metrics: %s", rr.Body.String())
	}

	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/status", nil))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"version":"0.1.0-test"`) {
		t.Fatalf("status: %s", rr.Body.String())
	}
}
