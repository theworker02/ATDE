package honeypot

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html"
	"html/template"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Site is the substantial fake "Atlas Control Plane" portal.
// It looks production-grade and vulnerability-rich; nothing is actually exploitable.
type Site struct {
	Brand       string
	HostHint    string
	mu          sync.Mutex
	failCount   map[string]int
	lockUntil   map[string]time.Time
	mfaPending  map[string]time.Time
}

func NewSite() *Site {
	return &Site{
		Brand:      "Atlas Control Plane",
		HostHint:   "ops-gateway-prod-01",
		failCount:  map[string]int{},
		lockUntil:  map[string]time.Time{},
		mfaPending: map[string]time.Time{},
	}
}

func (s *Site) setCommonHeaders(w http.ResponseWriter) {
	w.Header().Set("Server", "nginx/1.24.0")
	w.Header().Set("X-Powered-By", "PHP/8.1.27")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Request-Id", fakeRequestID())
	// Tempting misconfig signal — not a real debug panel.
	w.Header().Set("X-Debug-Token", "a7f3c2e1")
	w.Header().Set("X-Debug-Token-Link", "/_profiler/a7f3c2e1")
}

func fakeRequestID() string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	return hex.EncodeToString(sum[:8])
}

// RenderLanding serves a polished corporate landing page.
func (s *Site) RenderLanding(w http.ResponseWriter, r *http.Request) {
	s.setCommonHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = landingTmpl.Execute(w, s.pageData(r, "", ""))
}

func (s *Site) RenderLogin(w http.ResponseWriter, r *http.Request, flash string) {
	s.setCommonHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Plant HTML comments scanners love — never real credentials.
	w.Header().Set("Set-Cookie", "atlas_csrf="+fakeRequestID()+"; Path=/; HttpOnly; SameSite=Lax")
	_ = loginTmpl.Execute(w, s.pageData(r, flash, "Sign in"))
}

func (s *Site) RenderWPLogin(w http.ResponseWriter, r *http.Request, flash string) {
	s.setCommonHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = wpLoginTmpl.Execute(w, s.pageData(r, flash, "Log In"))
}

func (s *Site) RenderAdminLocked(w http.ResponseWriter, r *http.Request) {
	s.setCommonHeaders(w)
	http.SetCookie(w, &http.Cookie{Name: "wordpress_test_cookie", Value: "WP+Cookie+check", Path: "/"})
	// Cookie looks authenticated; gate never honors it.
	http.SetCookie(w, &http.Cookie{Name: "atlas_session", Value: "pending." + fakeRequestID(), Path: "/", HttpOnly: true})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_ = adminLockedTmpl.Execute(w, s.pageData(r, "Session expired or insufficient privilege.", "Admin"))
}

func (s *Site) RenderMFA(w http.ResponseWriter, r *http.Request, flash string) {
	s.setCommonHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = mfaTmpl.Execute(w, s.pageData(r, flash, "Two-factor authentication"))
}

func (s *Site) pageData(r *http.Request, flash, title string) map[string]any {
	if title == "" {
		title = s.Brand
	}
	return map[string]any{
		"Brand":    s.Brand,
		"Host":     s.HostHint,
		"Title":    title,
		"Flash":    flash,
		"Year":     time.Now().Year(),
		"Path":     r.URL.Path,
		"Canary":   "ATDE-CANARY-" + fakeRequestID()[:12],
		"CSS":      template.CSS(portalCSS),
	}
}

// AttemptLogin never authenticates. It burns time, emits realistic errors, and may
// open a dead-end MFA challenge. SQLi/payloads get specially crafted false leads.
func (s *Site) AttemptLogin(ip, user, pass, path string) (next string, flash string, delay time.Duration) {
	key := ip + "|" + path
	s.mu.Lock()
	defer s.mu.Unlock()

	if until, ok := s.lockUntil[key]; ok && time.Now().Before(until) {
		return "locked", "Account temporarily locked. Contact security operations.", 2 * time.Second
	}

	s.failCount[key]++
	n := s.failCount[key]
	delay = time.Duration(200+n*150) * time.Millisecond
	if delay > 3*time.Second {
		delay = 3 * time.Second
	}

	u := strings.ToLower(user)
	p := strings.ToLower(pass)
	combined := u + " " + p

	// Classic injection probes — look vulnerable, never yield a session.
	if looksSQLi(combined) {
		flash = `Warning: pg_query(): Query failed: ERROR:  syntax error at or near "'" LINE 1: ...WHERE user='` + html.EscapeString(truncateRunes(user, 40)) + `'--`
		if n >= 3 {
			s.lockUntil[key] = time.Now().Add(10 * time.Minute)
			return "locked", flash + " — WAF rule ATLAS-SQLI-17 tripped; account quarantined.", delay
		}
		return "login", flash, delay
	}
	if looksXSS(combined) || looksPathTraversal(combined) {
		return "login", "Security filter blocked malformed input (rule ATLAS-XSS-9).", delay
	}
	if looksDefaultCreds(u, p) {
		// Tempt then MFA dead-end — "almost in"
		s.mfaPending[key] = time.Now().Add(5 * time.Minute)
		return "mfa", "Additional verification required for privileged role.", delay + 400*time.Millisecond
	}

	if n >= 5 {
		s.lockUntil[key] = time.Now().Add(15 * time.Minute)
		return "locked", "Too many failed attempts. Identity provider lockout engaged.", delay
	}
	if n == 4 {
		s.mfaPending[key] = time.Now().Add(5 * time.Minute)
		return "mfa", "Unusual login location detected. Enter the authenticator code.", delay
	}

	msgs := []string{
		"Invalid username or password.",
		"Authentication failed for directory bind.",
		"LDAP error 49: Invalid credentials.",
		"Password expired — reset via corporate SSO (unavailable on this node).",
	}
	return "login", msgs[n%len(msgs)], delay
}

// AttemptMFA never accepts a code.
func (s *Site) AttemptMFA(ip, code, path string) (flash string, delay time.Duration) {
	key := ip + "|" + path
	s.mu.Lock()
	defer s.mu.Unlock()
	delay = 800 * time.Millisecond
	if _, ok := s.mfaPending[key]; !ok {
		return "MFA session expired. Sign in again.", delay
	}
	c := strings.TrimSpace(code)
	if len(c) == 6 && onlyDigits(c) {
		return "Invalid authenticator code. 2 of 3 attempts remaining.", delay + time.Second
	}
	if c == "000000" || c == "123456" {
		return "Code rejected by hardware token service (HTS-422).", delay + 1500*time.Millisecond
	}
	return "Verification failed. Contact on-call if you believe this is an error.", delay
}

func looksSQLi(s string) bool {
	needles := []string{"'", "\"", "--", "/*", "*/", " or 1=1", "or 1=1", "union select", "drop table", "sleep(", "benchmark(", "' or '", "'--"}
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func looksXSS(s string) bool {
	return strings.Contains(s, "<script") || strings.Contains(s, "javascript:") || strings.Contains(s, "onerror=")
}

func looksPathTraversal(s string) bool {
	return strings.Contains(s, "../") || strings.Contains(s, "..\\") || strings.Contains(s, "%2e%2e")
}

func looksDefaultCreds(u, p string) bool {
	defaults := [][2]string{
		{"admin", "admin"}, {"admin", "password"}, {"admin", "123456"},
		{"root", "root"}, {"administrator", "administrator"},
		{"test", "test"}, {"guest", "guest"}, {"admin", "admin123"},
	}
	for _, d := range defaults {
		if u == d[0] && p == d[1] {
			return true
		}
	}
	return false
}

func onlyDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

const portalCSS = `
:root{--bg:#0b1220;--panel:#121a2b;--ink:#e8eef7;--muted:#8b9bb4;--accent:#3d8bfd;--danger:#e85d5d;--ok:#3dd68c;--line:#243044;--warn:#e6b84d}
*{box-sizing:border-box}body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:radial-gradient(1200px 600px at 10% -10%,#1a2744 0%,var(--bg) 55%);color:var(--ink);min-height:100vh}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:1080px;margin:0 auto;padding:32px 20px 64px}
.nav{display:flex;justify-content:space-between;align-items:center;margin-bottom:40px}
.brand{display:flex;gap:12px;align-items:center;font-weight:700;letter-spacing:.02em}
.mark{width:36px;height:36px;border-radius:10px;background:linear-gradient(135deg,#3d8bfd,#6ee7b7);display:grid;place-items:center;color:#061018;font-size:14px}
.hero{display:grid;grid-template-columns:1.2fr .8fr;gap:28px;align-items:stretch}
@media(max-width:860px){.hero{grid-template-columns:1fr}}
.card{background:rgba(18,26,43,.92);border:1px solid var(--line);border-radius:16px;padding:28px;box-shadow:0 20px 50px rgba(0,0,0,.35)}
h1{font-size:clamp(1.8rem,3vw,2.6rem);line-height:1.15;margin:0 0 12px}
.lead{color:var(--muted);font-size:1.05rem;line-height:1.55;margin:0 0 22px}
.btn{display:inline-block;background:var(--accent);color:#fff;border:0;border-radius:10px;padding:12px 18px;font-weight:600;cursor:pointer}
.btn.secondary{background:transparent;border:1px solid var(--line);color:var(--ink)}
.meta{display:flex;flex-wrap:wrap;gap:10px;margin-top:18px}
.chip{font-size:12px;border:1px solid var(--line);border-radius:999px;padding:6px 10px;color:var(--muted)}
label{display:block;font-size:13px;color:var(--muted);margin:14px 0 6px}
input{width:100%;padding:12px 14px;border-radius:10px;border:1px solid var(--line);background:#0a101c;color:var(--ink)}
.flash{background:rgba(232,93,93,.12);border:1px solid rgba(232,93,93,.35);color:#ffd0d0;padding:12px 14px;border-radius:10px;margin:12px 0;font-size:14px;white-space:pre-wrap}
.flash.warn{background:rgba(230,184,77,.12);border-color:rgba(230,184,77,.4);color:#ffe6a8}
.foot{margin-top:36px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:16px}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:22px}
@media(max-width:860px){.grid{grid-template-columns:1fr}}
.tile{padding:16px;border:1px solid var(--line);border-radius:12px;background:#0d1524}
.tile h3{margin:0 0 6px;font-size:14px}.tile p{margin:0;color:var(--muted);font-size:13px;line-height:1.45}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;color:var(--muted)}
table.status{width:100%;border-collapse:collapse;font-size:13px}table.status td{padding:8px 0;border-bottom:1px solid var(--line)}
.ok{color:var(--ok)}.bad{color:var(--danger)}.warn{color:var(--warn)}
`

var (
	landingTmpl   = template.Must(template.New("landing").Parse(landingHTML))
	loginTmpl     = template.Must(template.New("login").Parse(loginHTML))
	wpLoginTmpl   = template.Must(template.New("wp").Parse(wpLoginHTML))
	adminLockedTmpl = template.Must(template.New("admin").Parse(adminLockedHTML))
	mfaTmpl       = template.Must(template.New("mfa").Parse(mfaHTML))
)

const landingHTML = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{{.Brand}} — Secure operations gateway</title>
<style>{{.CSS}}</style>
<!-- TODO(ops): remove staging debug routes before cutover: /api/v1/debug /_profiler /.env -->
</head><body><div class="wrap">
<nav class="nav"><div class="brand"><div class="mark">A</div>{{.Brand}}</div>
<div class="mono">{{.Host}} · build 2024.09.1-hotfix</div></nav>
<section class="hero">
  <div class="card">
    <h1>Enterprise control for hybrid infrastructure</h1>
    <p class="lead">Monitor workloads, rotate credentials, and approve break-glass access across production clusters. Authorized personnel only.</p>
    <a class="btn" href="/login">Customer login</a>
    <a class="btn secondary" href="/status" style="margin-left:8px">System status</a>
    <div class="meta">
      <span class="chip">SSO / LDAP</span><span class="chip">Hardware MFA</span><span class="chip">Audit export</span>
    </div>
    <div class="grid">
      <div class="tile"><h3>Cluster health</h3><p>Realtime node heartbeats and drain workflows.</p></div>
      <div class="tile"><h3>Secrets vault</h3><p>Scoped tokens with break-glass approval chains.</p></div>
      <div class="tile"><h3>Compliance</h3><p>Immutable session transcripts for IR handoff.</p></div>
    </div>
  </div>
  <div class="card">
    <h3 style="margin-top:0">Gateway notices</h3>
    <table class="status">
      <tr><td>API edge</td><td class="ok">operational</td></tr>
      <tr><td>Identity provider</td><td class="ok">operational</td></tr>
      <tr><td>Backup console</td><td class="warn">degraded · use primary</td></tr>
      <tr><td>Legacy PHP bridge</td><td class="bad">maintenance</td></tr>
    </table>
    <p class="mono" style="margin-top:18px">canary={{.Canary}}</p>
    <p class="mono">If you reached this node via a threat intel sinkhole, your connection is being recorded.</p>
  </div>
</section>
<footer class="foot">© {{.Year}} Atlas Systems · Unauthorized access prohibited · {{.Brand}}</footer>
</div></body></html>`

const loginHTML = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{{.Title}} — {{.Brand}}</title>
<style>{{.CSS}}</style>
<!--
  DEV NOTE: auth query prototype (DO NOT SHIP):
  SELECT * FROM users WHERE email='$email' AND password='$password'
  bypass? try admin'--
-->
</head><body><div class="wrap">
<nav class="nav"><div class="brand"><div class="mark">A</div>{{.Brand}}</div><a href="/">Home</a></nav>
<div class="card" style="max-width:440px;margin:40px auto">
  <h1 style="font-size:1.6rem">Sign in</h1>
  <p class="lead" style="font-size:.95rem">Use your corporate directory credentials. Sessions require hardware MFA.</p>
  {{if .Flash}}<div class="flash">{{.Flash}}</div>{{end}}
  <form method="post" action="/login" autocomplete="off">
    <label for="user">Username or email</label>
    <input id="user" name="username" required placeholder="j.smith@company.com"/>
    <label for="pass">Password</label>
    <input id="pass" name="password" type="password" required/>
    <div style="margin-top:18px;display:flex;gap:10px;align-items:center">
      <button class="btn" type="submit">Continue</button>
      <a class="mono" href="/wp-login.php">legacy WordPress bridge</a>
    </div>
  </form>
  <p class="mono" style="margin-top:20px">Forgot password? Contact SOC — self-service reset disabled on this appliance.</p>
</div>
<footer class="foot">© {{.Year}} Atlas Systems · Node {{.Host}}</footer>
</div></body></html>`

const wpLoginHTML = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Log In ‹ Atlas WP Bridge</title>
<style>
body{background:#f0f0f1;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif}
.login{width:320px;margin:60px auto;padding:26px 24px;background:#fff;border:1px solid #c3c4c7;box-shadow:0 1px 3px rgba(0,0,0,.04)}
h1{text-align:center;font-size:20px}label{display:block;margin:12px 0 4px;font-size:14px}
input{width:100%;padding:6px 8px;border:1px solid #8c8f94;border-radius:4px}
.button{margin-top:16px;width:100%;background:#2271b1;border:1px solid #2271b1;color:#fff;padding:8px;border-radius:3px;font-weight:600}
.error{background:#fcf0f1;border-left:4px solid #d63638;padding:10px;margin:0 0 14px;font-size:13px}
</style>
</head><body>
<div class="login">
<h1>Atlas WP Bridge</h1>
{{if .Flash}}<div class="error">{{.Flash}}</div>{{end}}
<form method="post" action="/wp-login.php" name="loginform">
<label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login"/>
<label for="user_pass">Password</label>
<input type="password" name="pwd" id="user_pass"/>
<button class="button" type="submit">Log In</button>
</form>
<p style="font-size:12px;color:#646970;margin-top:16px"><a href="/login">← Corporate SSO</a></p>
</div>
<!-- plugin: rest-api exposed at /wp-json/wp/v2/users -->
</body></html>`

const adminLockedHTML = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Admin — {{.Brand}}</title>
<style>{{.CSS}}</style>
</head><body><div class="wrap">
<div class="card" style="max-width:560px;margin:48px auto">
  <h1 style="font-size:1.5rem">Console locked</h1>
  {{if .Flash}}<div class="flash warn">{{.Flash}}</div>{{end}}
  <p class="lead">Your browser presented a session cookie, but the control plane rejected privilege elevation. This node does not accept break-glass without hardware attestation.</p>
  <a class="btn" href="/login">Return to sign-in</a>
  <p class="mono" style="margin-top:18px">hint: /api/v1/admin/users.json requires Bearer token (not issued on honeypot nodes)</p>
</div></div></body></html>`

const mfaHTML = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{{.Title}} — {{.Brand}}</title>
<style>{{.CSS}}</style>
</head><body><div class="wrap">
<div class="card" style="max-width:440px;margin:48px auto">
  <h1 style="font-size:1.5rem">Two-factor authentication</h1>
  <p class="lead">Enter the 6-digit code from your enrolled hardware token.</p>
  {{if .Flash}}<div class="flash warn">{{.Flash}}</div>{{end}}
  <form method="post" action="/mfa">
    <label for="otp">Authenticator code</label>
    <input id="otp" name="otp" inputmode="numeric" pattern="[0-9]*" maxlength="8" placeholder="••••••" required/>
    <button class="btn" type="submit" style="margin-top:16px">Verify</button>
  </form>
  <p class="mono" style="margin-top:18px">SMS fallback disabled · Backup codes revoked on this appliance</p>
</div></div></body></html>`
