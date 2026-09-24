package honeypot

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/theworker02/blind-botnet/v2/internal/catch"
	"github.com/theworker02/blind-botnet/v2/internal/config"
	"github.com/theworker02/blind-botnet/v2/internal/disrupt/edge"
	"github.com/theworker02/blind-botnet/v2/internal/disrupt/tarpit"
	"github.com/theworker02/blind-botnet/v2/internal/fingerprint"
	"github.com/theworker02/blind-botnet/v2/internal/fleet"
	"github.com/theworker02/blind-botnet/v2/internal/models"
	"github.com/theworker02/blind-botnet/v2/internal/natsbus"
	"github.com/theworker02/blind-botnet/v2/internal/ops"
	"github.com/theworker02/blind-botnet/v2/internal/policy"
)

// Server publishes trap hits and serves the substantial Atlas decoy portal.
type Server struct {
	cfg     config.HoneypotConfig
	bus     *natsbus.Bus
	log     *slog.Logger
	tarpit  *tarpit.Engine
	ledger  *catch.Ledger
	site    *Site
	metrics *ops.Metrics
	blocker *edge.Blocker
	policy  *policy.Engine
	fleet   *fleet.Store

	hitMu    sync.Mutex
	hitCount map[string]int
}

func New(cfg config.HoneypotConfig, bus *natsbus.Bus, log *slog.Logger) *Server {
	return &Server{
		cfg: cfg, bus: bus, log: log,
		ledger:   catch.New("./data/caught"),
		site:     NewSite(),
		hitCount: map[string]int{},
	}
}

func (s *Server) WithLedger(l *catch.Ledger) *Server {
	if l != nil {
		s.ledger = l
	}
	return s
}

func (s *Server) WithMetrics(m *ops.Metrics) *Server {
	s.metrics = m
	return s
}

func (s *Server) WithTarpit(e *tarpit.Engine) *Server {
	s.tarpit = e
	return s
}

// WithBlocker enables local-first OS blocks after repeated public hits (no NATS required).
func (s *Server) WithBlocker(b *edge.Blocker) *Server {
	s.blocker = b
	return s
}

// WithPolicy attaches the graduated threat disruption policy engine (ATDE 2.0).
func (s *Server) WithPolicy(p *policy.Engine) *Server {
	s.policy = p
	return s
}

// WithFleet publishes local bans to the owned-node fleet ban list.
func (s *Server) WithFleet(f *fleet.Store) *Server {
	s.fleet = f
	return s
}

// Handler returns the HTTP handler (useful for tests without Listen).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.route)
	return mux
}

func (s *Server) Run(ctx context.Context) error {
	if !s.cfg.Enabled {
		s.log.Info("honeypot disabled")
		return nil
	}

	srv := &http.Server{
		Addr:              s.cfg.HTTPAddr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 8 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      0,
	}

	// Always use password-burn SSH so credentials are recorded.
	// HTTP tarpit paths still use s.tarpit when attached.
	go s.serveSSH(ctx.Done())
	go s.serveExtraBaits(ctx.Done())

	errCh := make(chan error, 1)
	go func() {
		s.log.Info("honeypot http listening",
			"addr", s.cfg.HTTPAddr,
			"portal", s.site.Brand,
			"ssh", s.cfg.SSHAddr,
			"redis", s.cfg.RedisAddr,
			"telnet", s.cfg.TelnetAddr,
			"http_tarpit", s.tarpit != nil,
		)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shCtx)
		return ctx.Err()
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Heavy tarpit paths — scanners starve here
	if s.shouldTarpit(path) {
		s.emitHit(r, "http-tarpit")
		if s.tarpit != nil {
			s.tarpit.HTTPHandler(w, r)
			return
		}
	}

	switch {
	case path == "/" || path == "/index.html":
		s.emitHit(r, "http-portal")
		s.site.RenderLanding(w, r)
	case path == "/login":
		s.handleLogin(w, r)
	case path == "/wp-login.php":
		s.handleWPLogin(w, r)
	case path == "/mfa":
		s.handleMFA(w, r)
	case path == "/admin" || strings.HasPrefix(path, "/admin/"):
		s.emitHit(r, "http-admin")
		s.site.RenderAdminLocked(w, r)
	case path == "/status":
		s.emitHit(r, "http-portal")
		s.site.ServeStatus(w, r)
	case path == "/docs":
		s.emitHit(r, "http-portal")
		s.site.ServeDocs(w, r)
	case path == "/robots.txt":
		s.emitHit(r, "http-recon")
		s.site.ServeRobots(w, r)
	case path == "/sitemap.xml":
		s.emitHit(r, "http-recon")
		s.site.ServeSitemap(w, r)
	case path == "/.well-known/security.txt":
		s.emitHit(r, "http-recon")
		s.site.ServeSecurityTxt(w, r)
	case path == "/openapi.json" || path == "/swagger.json":
		s.emitHit(r, "http-recon")
		s.site.ServeOpenAPI(w, r)
	case path == "/favicon.ico":
		s.emitHit(r, "http-recon")
		s.site.ServeFavicon(w, r)
	case path == "/.env" || path == "/config/.env" || path == "/app/.env":
		s.emitHit(r, "http-vuln-bait")
		s.site.ServeEnv(w, r)
	case path == "/.git/config":
		s.emitHit(r, "http-vuln-bait")
		s.site.ServeGitConfig(w, r)
	case path == "/.git/HEAD" || path == "/.git/":
		s.emitHit(r, "http-vuln-bait")
		s.site.ServeGitHEAD(w, r)
	case path == "/phpinfo.php" || path == "/info.php":
		s.emitHit(r, "http-vuln-bait")
		s.site.ServePHPInfo(w, r)
	case strings.HasPrefix(path, "/_profiler"):
		s.emitHit(r, "http-vuln-bait")
		s.site.ServeProfiler(w, r)
	case path == "/backup" || path == "/backup/":
		s.emitHit(r, "http-vuln-bait")
		s.site.ServeBackupListing(w, r)
	case strings.HasPrefix(path, "/backup/"):
		s.emitHit(r, "http-vuln-bait")
		s.site.ServeBackupFile(w, r)
	case strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/wp-json"):
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		s.emitHitWithBody(r, "http-api", body)
		s.site.ServeAPI(w, r)
	case path == "/canary":
		s.emitHit(r, "http-canary")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ATDE-HONEYPOT-OK\n"))
	default:
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		s.emitHitWithBody(r, "http", body)
		s.site.RenderLanding(w, r)
	}
}

func (s *Server) shouldTarpit(path string) bool {
	for _, p := range []string{"/tarpit", "/cgi-bin/", "/vendor/phpunit", "/actuator/heapdump"} {
		if path == p || strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.emitHit(r, "http-login")
		s.site.RenderLogin(w, r, "")
		return
	}
	_ = r.ParseForm()
	user := r.FormValue("username")
	if user == "" {
		user = r.FormValue("log")
	}
	pass := r.FormValue("password")
	if pass == "" {
		pass = r.FormValue("pwd")
	}
	body := []byte(user + ":" + pass)
	s.emitHitWithBody(r, "http-login-post", body)

	ip := remoteIP(r)
	next, flash, delay := s.site.AttemptLogin(ip, user, pass, "/login")
	time.Sleep(delay)
	switch next {
	case "mfa":
		s.site.RenderMFA(w, r, flash)
	case "locked":
		s.site.RenderLogin(w, r, flash)
	default:
		s.site.RenderLogin(w, r, flash)
	}
}

func (s *Server) handleWPLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.emitHit(r, "http-wp-login")
		s.site.RenderWPLogin(w, r, "")
		return
	}
	_ = r.ParseForm()
	user := r.FormValue("log")
	pass := r.FormValue("pwd")
	s.emitHitWithBody(r, "http-wp-login-post", []byte(user+":"+pass))
	ip := remoteIP(r)
	next, flash, delay := s.site.AttemptLogin(ip, user, pass, "/wp-login.php")
	time.Sleep(delay)
	if next == "mfa" {
		http.Redirect(w, r, "/mfa", http.StatusFound)
		return
	}
	s.site.RenderWPLogin(w, r, flash)
}

func (s *Server) handleMFA(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.emitHit(r, "http-mfa")
		s.site.RenderMFA(w, r, "")
		return
	}
	_ = r.ParseForm()
	otp := r.FormValue("otp")
	s.emitHitWithBody(r, "http-mfa-post", []byte(otp))
	flash, delay := s.site.AttemptMFA(remoteIP(r), otp, "/login")
	time.Sleep(delay)
	s.site.RenderMFA(w, r, flash)
}

func (s *Server) emitHit(r *http.Request, service string) {
	s.emitHitWithBody(r, service, nil)
}

func (s *Server) emitHitWithBody(r *http.Request, service string, body []byte) {
	now := time.Now().UTC()
	ip := remoteIP(r)
	bodyStr := string(body)
	fp := fingerprint.FromHTTP(r, bodyStr)
	evt := models.RawHoneypotEvent{
		ID:        "evt_raw_hp_" + now.Format("20060102150405.000000"),
		Timestamp: now,
		Source:    "honeypot",
		Data: models.HoneypotData{
			Service:    service,
			RemoteAddr: ip,
			Path:       r.URL.Path,
			Method:     r.Method,
			UserAgent:  r.UserAgent(),
			Headers:    pickHeaders(r),
			BodyB64:    base64.StdEncoding.EncodeToString(body),
		},
	}
	actions := []string{"recorded"}
	if strings.Contains(service, "tarpit") {
		actions = append(actions, "tarpit")
	}
	if strings.Contains(service, "login") || strings.Contains(service, "mfa") {
		actions = append(actions, "auth_burn")
	}
	if s.metrics != nil {
		s.metrics.HoneypotHits.Add(1)
		if strings.Contains(service, "login") || strings.Contains(service, "mfa") {
			s.metrics.AuthBurns.Add(1)
		}
		if strings.Contains(service, "vuln-bait") {
			s.metrics.VulnBaitHits.Add(1)
		}
	}
	if s.ledger != nil {
		meta := map[string]string{}
		if len(body) > 0 {
			snippet := bodyStr
			if len(snippet) > 512 {
				snippet = snippet[:512] + "…"
			}
			meta["body_snippet"] = snippet
		}
		if fp.Tool != "" {
			meta["tool"] = fp.Tool
		}
		rec := catch.Record{
			ID: "catch_" + evt.ID, CaughtAt: now, Source: "honeypot",
			IP: ip, Service: service, Path: r.URL.Path, Method: r.Method,
			UserAgent: r.UserAgent(), Reason: "honeypot_hit", Actions: actions,
			Meta: meta, Tags: fp.Tags, Tool: fp.Tool, Severity: fp.Severity, Summary: fp.Summary,
			Techniques: fp.Techniques,
		}
		_ = s.ledger.Record(rec)
		if s.metrics != nil {
			s.metrics.CatchRecords.Add(1)
		}
	}
	if s.bus != nil {
		raw, _ := json.Marshal(evt)
		if _, err := s.bus.Publish(models.SubjectRawHoneypot, raw); err != nil {
			s.log.Error("publish honeypot", "err", err)
		}
	}
	s.maybeBlock(ip, fp.Severity, service)
	s.log.Info("honeypot hit", "service", service, "path", r.URL.Path, "remote", ip, "tool", fp.Tool, "sev", fp.Severity, "id", evt.ID)
}

func (s *Server) maybeBlock(ip string, severity int, reason string) {
	if ip == "" {
		return
	}
	if s.policy != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			d := s.policy.Apply(ctx, ip, severity, reason)
			if s.metrics != nil && (d.Tier == policy.TierLocalBan || d.Tier == policy.TierCloud) {
				s.metrics.DisruptBlocks.Add(1)
			}
			if s.fleet != nil && (d.Tier == policy.TierLocalBan || d.Tier == policy.TierCloud) {
				_ = s.fleet.Upsert(fleet.BanEntry{
					IP: ip, Reason: reason, Severity: severity, Tier: string(d.Tier),
				})
			}
		}()
		return
	}
	if s.blocker == nil {
		return
	}
	threshold := s.cfg.BlockAfter
	if threshold <= 0 {
		threshold = 3
	}
	if severity < 40 {
		return
	}
	s.hitMu.Lock()
	s.hitCount[ip]++
	n := s.hitCount[ip]
	s.hitMu.Unlock()
	if n < threshold {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		res := s.blocker.EnforceContainment(ctx, ip, "honeypot:"+reason, 0.95, false)
		if res.LocalOK {
			s.log.Info("local block applied", "ip", ip, "hits", n)
			if s.metrics != nil {
				s.metrics.LocalBlocksOK.Add(1)
				s.metrics.DisruptBlocks.Add(1)
			}
			if s.ledger != nil {
				_ = s.ledger.Record(catch.Record{
					ID: "catch_block_" + time.Now().UTC().Format("20060102150405.000000"),
					CaughtAt: time.Now().UTC(), Source: "active", IP: ip,
					Reason: "local_firewall", Actions: []string{"local_firewall"},
					Blocked: true, Severity: severity, Summary: "OS firewall ban",
					Tags: []string{"blocked"},
				})
			}
			if s.fleet != nil {
				_ = s.fleet.Upsert(fleet.BanEntry{IP: ip, Reason: reason, Severity: severity, Tier: "local_ban"})
			}
		}
	}()
}

func remoteIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func pickHeaders(r *http.Request) map[string]string {
	out := map[string]string{}
	for _, k := range []string{"Content-Type", "Authorization", "Referer", "Cookie"} {
		if v := r.Header.Get(k); v != "" {
			out[k] = v
		}
	}
	return out
}
