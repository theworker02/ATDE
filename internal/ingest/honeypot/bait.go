package honeypot

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"
)

// Fake vuln / juicy-file responses. All content is synthetic canary material.

func (s *Site) ServeSecurityTxt(w http.ResponseWriter, _ *http.Request) {
	s.setCommonHeaders(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(`Contact: mailto:security@atlas.invalid
Expires: 2027-01-01T00:00:00.000Z
Preferred-Languages: en
Canonical: https://ops.atlas.invalid/.well-known/security.txt
Policy: https://ops.atlas.invalid/security-policy
Acknowledgments: This node is an ATDE honeypot — reports of "exploits" against it are expected scanner noise.
`))
}

func (s *Site) ServeOpenAPI(w http.ResponseWriter, _ *http.Request) {
	s.setCommonHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":       "Atlas Control Plane API",
			"version":     "2024.09.1",
			"description": "Requires SSO Bearer tokens. Honeypot nodes never mint tokens.",
		},
		"servers": []map[string]string{{"url": "/api/v1"}},
		"paths": map[string]any{
			"/health": map[string]any{"get": map[string]any{"summary": "Liveness"}},
			"/admin/users": map[string]any{
				"get": map[string]any{
					"summary": "List users",
					"security": []map[string][]string{{"bearerAuth": {}}},
					"responses": map[string]any{"401": map[string]string{"description": "Unauthorized"}},
				},
			},
			"/debug": map[string]any{
				"get": map[string]any{
					"summary": "Internal debug (disabled on honeypot — synthetic only)",
					"parameters": []map[string]any{{
						"name": "cmd", "in": "query", "schema": map[string]string{"type": "string"},
					}},
				},
			},
		},
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"bearerAuth": map[string]string{"type": "http", "scheme": "bearer"},
			},
		},
	})
}

func (s *Site) ServeFavicon(w http.ResponseWriter, _ *http.Request) {
	s.setCommonHeaders(w)
	w.Header().Set("Content-Type", "image/svg+xml")
	_, _ = w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="#121a2b"/><text x="16" y="22" text-anchor="middle" font-size="16" fill="#3d8bfd" font-family="sans-serif">A</text></svg>`))
}

func (s *Site) ServeEnv(w http.ResponseWriter, _ *http.Request) {
	s.setCommonHeaders(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(`# Atlas appliance env (CANARY — not production secrets)
APP_ENV=production
APP_DEBUG=true
APP_KEY=base64:ATDE_CANARY_KEY_DO_NOT_USE_` + fakeRequestID() + `
DB_CONNECTION=pgsql
DB_HOST=127.0.0.1
DB_PORT=5432
DB_DATABASE=atlas_ops
DB_USERNAME=atlas_ro
DB_PASSWORD=CanaryPassword!NotReal-` + fakeRequestID()[:8] + `
AWS_ACCESS_KEY_ID=AKIA` + strings.ToUpper(fakeRequestID()[:16]) + `
AWS_SECRET_ACCESS_KEY=wJalr/` + fakeRequestID() + `canary
JWT_SECRET=atde-honeypot-jwt-canary-` + fakeRequestID() + `
REDIS_URL=redis://127.0.0.1:6379/0
TELEGRAM_BOT_TOKEN=0000000000:AAHoneypotCanaryTokenNotRealXXXXX
`))
}

func (s *Site) ServeGitConfig(w http.ResponseWriter, _ *http.Request) {
	s.setCommonHeaders(w)
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote \"origin\"]\n\turl = https://git.internal.atlas.invalid/ops/gateway.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[user]\n\tname = deploy\n\temail = deploy@atlas.invalid\n"))
}

func (s *Site) ServeGitHEAD(w http.ResponseWriter, _ *http.Request) {
	s.setCommonHeaders(w)
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ref: refs/heads/main\n"))
}

func (s *Site) ServePHPInfo(w http.ResponseWriter, _ *http.Request) {
	s.setCommonHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html><html><head><title>phpinfo()</title>
<style>body{background:#fff;color:#222;font-family:sans-serif}h1{background:#9999cc;padding:8px}.e{background:#ccccff;padding:4px}.v{background:#cccccc;padding:4px}</style>
</head><body>
<h1>PHP Version 8.1.27</h1>
<table>
<tr><td class="e">System</td><td class="v">Linux ` + s.HostHint + ` 5.15.0-105-generic #x86_64</td></tr>
<tr><td class="e">Server API</td><td class="v">FPM/FastCGI</td></tr>
<tr><td class="e">Configuration File (php.ini)</td><td class="v">/etc/php/8.1/fpm/php.ini</td></tr>
<tr><td class="e">display_errors</td><td class="v">On</td></tr>
<tr><td class="e">allow_url_include</td><td class="v">On</td></tr>
<tr><td class="e">disable_functions</td><td class="v"><i>no value</i></td></tr>
</table>
<p><em>Atlas honeypot canary — phpinfo is simulated; no interpreter is exposed.</em></p>
</body></html>`))
}

func (s *Site) ServeRobots(w http.ResponseWriter, _ *http.Request) {
	s.setCommonHeaders(w)
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(`User-agent: *
Disallow: /admin
Disallow: /backup
Disallow: /api/v1/debug
Disallow: /.env
Disallow: /_profiler
Allow: /
Sitemap: /sitemap.xml
`))
}

func (s *Site) ServeSitemap(w http.ResponseWriter, _ *http.Request) {
	s.setCommonHeaders(w)
	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>/login</loc></url>
  <url><loc>/status</loc></url>
  <url><loc>/docs</loc></url>
</urlset>`))
}

func (s *Site) ServeStatus(w http.ResponseWriter, r *http.Request) {
	s.setCommonHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = statusPageTmpl.Execute(w, s.pageData(r, "", "System status"))
}

func (s *Site) ServeDocs(w http.ResponseWriter, r *http.Request) {
	s.setCommonHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = docsPageTmpl.Execute(w, s.pageData(r, "", "API docs"))
}

func (s *Site) ServeAPI(w http.ResponseWriter, r *http.Request) {
	s.setCommonHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	path := r.URL.Path

	switch {
	case strings.HasPrefix(path, "/api/v1/debug"), strings.Contains(r.URL.RawQuery, "cmd="):
		time.Sleep(600 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true,"host":"` + s.HostHint + `","stdout":"uid=0(root) gid=0(root) groups=0(root)\n","note":"synthetic rce canary — no shell executed","canary":"ATDE-RCE-` + fakeRequestID()[:10] + `"}`))
		return
	case strings.HasPrefix(path, "/api/v1/admin"), strings.HasPrefix(path, "/wp-json"):
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":   "unauthorized",
			"message": "Bearer token required",
			"hint":    "Obtain token via /oauth/token (SSO only)",
			"request": fakeRequestID(),
		})
		return
	case strings.HasPrefix(path, "/api/v1/storage"):
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":  "forbidden",
			"bucket": "atlas-prod-backups",
			"reason": "object ACL denies anonymous ListBucket",
		})
		return
	case path == "/api/v1/health":
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "node": s.HostHint, "ts": time.Now().UTC()})
		return
	default:
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "unauthorized",
			"path":  path,
			"docs":  "/docs",
			"login": "/login",
		})
	}
}

func (s *Site) ServeProfiler(w http.ResponseWriter, _ *http.Request) {
	s.setCommonHeaders(w)
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `<html><body><h1>Symfony Profiler</h1><p>Token a7f3c2e1 — <em>canary panel</em></p>
<pre>database: 14 queries (0 real)
security: anonymous token; firewall "main" would deny elevation
exception: none</pre>
<p>No interactive tooling is available on honeypot nodes.</p></body></html>`)
}

func (s *Site) ServeBackupListing(w http.ResponseWriter, _ *http.Request) {
	s.setCommonHeaders(w)
	w.Header().Set("Content-Type", "text/html")
	_, _ = w.Write([]byte(`<!doctype html><title>Index of /backup</title>
<h1>Index of /backup</h1><pre>
<a href="/backup/">../</a>
<a href="/backup/db.sql.gz">db.sql.gz</a>                 2024-08-01 03:11  184M
<a href="/backup/secrets.env.bak">secrets.env.bak</a>        2024-08-01 03:11  2.1K
<a href="/backup/id_rsa">id_rsa</a>                     2024-07-12 11:02  1.7K
</pre>
<p>Downloads return 403 — canary listing only.</p>`))
}

func (s *Site) ServeBackupFile(w http.ResponseWriter, _ *http.Request) {
	s.setCommonHeaders(w)
	time.Sleep(400 * time.Millisecond)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"error":"forbidden","message":"backup objects are not anonymously readable","canary":true}`))
}

const statusPageHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"/><title>{{.Title}}</title><style>{{.CSS}}</style></head>
<body><div class="wrap">
<nav class="nav"><div class="brand"><div class="mark">A</div>{{.Brand}}</div><a href="/login">Login</a></nav>
<div class="card">
<h1 style="font-size:1.6rem">System status</h1>
<table class="status">
<tr><td>Control API</td><td class="ok">operational</td></tr>
<tr><td>Auth (LDAP)</td><td class="ok">operational</td></tr>
<tr><td>MFA service</td><td class="ok">operational</td></tr>
<tr><td>Object storage</td><td class="warn">read-only mode</td></tr>
<tr><td>Legacy bridge</td><td class="bad">maintenance window</td></tr>
</table>
<p class="mono" style="margin-top:16px">incident channel: #atlas-ops · node {{.Host}}</p>
</div></div></body></html>`

const docsPageHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"/><title>{{.Title}}</title><style>{{.CSS}}</style></head>
<body><div class="wrap">
<nav class="nav"><div class="brand"><div class="mark">A</div>{{.Brand}}</div><a href="/">Home</a></nav>
<div class="card">
<h1 style="font-size:1.6rem">API reference (excerpt)</h1>
<p class="lead">All mutating endpoints require a scoped Bearer token issued by corporate SSO. This appliance does not mint tokens for anonymous clients.</p>
<pre class="mono" style="background:#0a101c;padding:14px;border-radius:10px;overflow:auto">
GET  /api/v1/health
GET  /api/v1/admin/users      → 401 without Bearer
POST /api/v1/debug?cmd=id     → synthetic canary output only
GET  /wp-json/wp/v2/users     → 401
</pre>
<p class="mono">OpenAPI: /openapi.json (auth required)</p>
</div></div></body></html>`

var (
	statusPageTmpl = template.Must(template.New("statusPage").Parse(statusPageHTML))
	docsPageTmpl   = template.Must(template.New("docsPage").Parse(docsPageHTML))
)
