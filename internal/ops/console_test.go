package ops

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/theworker02/blind-botnet/internal/catch"
)

func TestCatchAPIAndConsole(t *testing.T) {
	dir := t.TempDir()
	l := catch.New(dir)
	_ = l.Record(catch.Record{Source: "honeypot", IP: "203.0.113.77", Service: "http", Path: "/.env", Reason: "vuln_bait"})

	h := &Handler{
		Metrics: NewMetrics("test", "all"),
		Ready:   func() bool { return true },
		Catch:   &CatchAPI{Ledger: l, Token: "secret"},
	}
	mux := http.NewServeMux()
	h.Mount(mux)

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/dossiers", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/dossiers?limit=10", nil)
	req.Header.Set("X-ATDE-Token", "secret")
	mux.ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "203.0.113.77") {
		t.Fatalf("dossiers: %d %s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/console?token=secret", nil)
	mux.ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "Live Catch Console") {
		t.Fatalf("console: %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v1/summary?token=secret", nil)
	mux.ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "unique_ips") {
		t.Fatalf("summary: %s", rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v1/export/203.0.113.77?token=secret", nil)
	mux.ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "catch package") {
		t.Fatalf("export: %s", rr.Body.String())
	}
}
