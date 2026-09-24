package honeypot_test

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/theworker02/ATDE/v2/internal/config"
	"github.com/theworker02/ATDE/v2/internal/ingest/honeypot"
	"github.com/theworker02/ATDE/v2/internal/ops"
)

func testServer(t *testing.T) *honeypot.Server {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return honeypot.New(config.HoneypotConfig{Enabled: true, HTTPAddr: ":0", SSHAddr: ":0"}, nil, log)
}

func TestLandingLooksReal(t *testing.T) {
	srv := testServer(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d", rr.Code)
	}
	body := rr.Body.String()
	for _, needle := range []string{"Atlas Control Plane", "Customer login", "Hardware MFA", "canary="} {
		if !strings.Contains(body, needle) {
			t.Fatalf("missing %q in landing", needle)
		}
	}
	if rr.Header().Get("X-Debug-Token-Link") == "" {
		t.Fatal("expected tempting debug header")
	}
}

func TestLoginNeverSucceeds(t *testing.T) {
	srv := testServer(t)
	form := url.Values{"username": {"admin"}, "password": {"correct-horse-battery"}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.10:443"
	start := time.Now()
	srv.Handler().ServeHTTP(rr, req)
	if time.Since(start) < 150*time.Millisecond {
		t.Fatal("expected auth burn delay")
	}
	body := rr.Body.String()
	if strings.Contains(body, "Dashboard") && !strings.Contains(body, "Sign in") {
		t.Fatalf("must not grant dashboard access: %s", body[:min(200, len(body))])
	}
	if !strings.Contains(body, "Invalid") && !strings.Contains(body, "failed") && !strings.Contains(body, "LDAP") {
		t.Fatalf("expected failure flash, got: %s", body[:min(300, len(body))])
	}
}

func TestSQLiGetsFakeErrorNeverSession(t *testing.T) {
	site := honeypot.NewSite()
	next, flash, _ := site.AttemptLogin("198.51.100.1", "admin'--", "x", "/login")
	if next == "ok" || next == "admin" {
		t.Fatal("SQLi must not authenticate")
	}
	if !strings.Contains(strings.ToLower(flash), "syntax") && !strings.Contains(flash, "pg_query") {
		t.Fatalf("expected fake SQL error, got %q", flash)
	}
}

func TestDefaultCredsLeadToDeadEndMFA(t *testing.T) {
	site := honeypot.NewSite()
	next, _, _ := site.AttemptLogin("198.51.100.2", "admin", "admin", "/login")
	if next != "mfa" {
		t.Fatalf("want mfa dead-end, got %s", next)
	}
	flash, _ := site.AttemptMFA("198.51.100.2", "123456", "/login")
	if strings.Contains(strings.ToLower(flash), "success") {
		t.Fatal("MFA must never succeed")
	}
}

func TestEnvBaitIsCanary(t *testing.T) {
	srv := testServer(t)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/.env", nil))
	body := rr.Body.String()
	if !strings.Contains(body, "CANARY") || !strings.Contains(body, "JWT_SECRET=") {
		t.Fatalf("expected canary env: %s", body[:min(200, len(body))])
	}
}

func TestAdminLockedDespiteCookie(t *testing.T) {
	srv := testServer(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(&http.Cookie{Name: "atlas_session", Value: "forged.admin.token"})
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Console locked") {
		t.Fatal("expected locked admin page")
	}
}

func TestAPIAdminUnauthorized(t *testing.T) {
	srv := testServer(t)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rr.Code)
	}
}

func TestDebugRCEIsSynthetic(t *testing.T) {
	srv := testServer(t)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/debug?cmd=id", nil))
	body := rr.Body.String()
	if !strings.Contains(body, "uid=0(root)") || !strings.Contains(body, "synthetic") {
		t.Fatalf("expected synthetic rce canary: %s", body)
	}
}

func TestWPLoginPage(t *testing.T) {
	srv := testServer(t)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/wp-login.php", nil))
	if !strings.Contains(rr.Body.String(), "Atlas WP Bridge") {
		t.Fatal("expected WP skin")
	}
}

func TestOpenAPIAndSecurityTxt(t *testing.T) {
	srv := testServer(t)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/openapi.json", nil))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"openapi"`) {
		t.Fatalf("openapi: %s", rr.Body.String())
	}
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/.well-known/security.txt", nil))
	if !strings.Contains(rr.Body.String(), "honeypot") {
		t.Fatal("expected security.txt honeypot notice")
	}
}

func TestMetricsWiredOnHit(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := ops.NewMetrics("test", "honeypot")
	srv := honeypot.New(config.HoneypotConfig{Enabled: true}, nil, log).WithMetrics(m)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/.env", nil))
	if m.HoneypotHits.Load() < 1 {
		t.Fatal("expected honeypot hit counter")
	}
	if m.VulnBaitHits.Load() < 1 {
		t.Fatal("expected vuln bait counter")
	}
}

func TestSSHPasswordBurn(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := ops.NewMetrics("test", "honeypot")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	srv := honeypot.New(config.HoneypotConfig{
		Enabled: true, HTTPAddr: ":0", SSHAddr: addr,
	}, nil, log).WithMetrics(m)

	done := make(chan struct{})
	go srv.StartSSH(done)
	defer close(done)

	deadline := time.Now().Add(3 * time.Second)
	var conn net.Conn
	for time.Now().Before(deadline) {
		conn, err = net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if conn == nil {
		t.Fatalf("dial ssh honeypot: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "OpenSSH") {
		t.Fatalf("banner: %q err=%v", string(buf[:n]), err)
	}
	_, _ = conn.Write([]byte("SSH-2.0-testhost\r\n"))

	// Drain until password prompt, then send credentials twice.
	deadline = time.Now().Add(4 * time.Second)
	gotLogin := false
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, err = conn.Read(buf)
		chunk := string(buf[:max(0, n)])
		if strings.Contains(chunk, "login as:") && !gotLogin {
			_, _ = conn.Write([]byte("root\n"))
			gotLogin = true
		}
		if strings.Contains(chunk, "password:") {
			_, _ = conn.Write([]byte("toor\n"))
		}
		if m.AuthBurns.Load() >= 1 {
			return
		}
		if err != nil && !strings.Contains(err.Error(), "timeout") {
			break
		}
	}
	if m.AuthBurns.Load() < 1 {
		t.Fatalf("expected auth burn metric, hits=%d burns=%d", m.HoneypotHits.Load(), m.AuthBurns.Load())
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func BenchmarkLanding(b *testing.B) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := honeypot.New(config.HoneypotConfig{Enabled: true}, nil, log)
	h := srv.Handler()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	}
}

func BenchmarkAttemptLogin(b *testing.B) {
	site := honeypot.NewSite()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, _ = site.AttemptLogin("203.0.113.9", "user", "pass", "/login")
	}
}

func BenchmarkEnvBait(b *testing.B) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := honeypot.New(config.HoneypotConfig{Enabled: true}, nil, log)
	h := srv.Handler()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/.env", nil))
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
