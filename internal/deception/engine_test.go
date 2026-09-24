package deception_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/theworker02/ATDE/v2/internal/config"
	"github.com/theworker02/ATDE/v2/internal/deception"
)

func TestRCEDecoySynthetic(t *testing.T) {
	e := deception.New(config.DeceptionConfig{Enabled: true, ListenAddr: ":0", MaxDelay: time.Millisecond}, nil, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/debug?cmd=id", nil)
	rr := httptest.NewRecorder()
	e.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "uid=0(root)") {
		t.Fatalf("unexpected body: %s", rr.Body.String())
	}
}

func TestDotEnvDecoy(t *testing.T) {
	e := deception.New(config.DeceptionConfig{Enabled: true, MaxDelay: time.Millisecond}, nil, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/.env", nil)
	rr := httptest.NewRecorder()
	e.ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "JWT_SECRET=") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}
