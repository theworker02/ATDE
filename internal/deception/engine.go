package deception

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/theworker02/blind-botnet/v2/internal/config"
	"github.com/theworker02/blind-botnet/v2/internal/immunize"
	"github.com/theworker02/blind-botnet/v2/internal/models"
	"github.com/theworker02/blind-botnet/v2/internal/natsbus"
)

// Engine is the deceptive L7 surface: realistic vuln indicators, zero real exploitability.
type Engine struct {
	cfg      config.DeceptionConfig
	bus      *natsbus.Bus
	log      *slog.Logger
	decoys   []Decoy
	sessions map[string]*Session
	mu       sync.RWMutex
	proxy    *httputil.ReverseProxy
	reporter *ThreatReporter
	trusted  []*net.IPNet
}

type Decoy struct {
	Name        string
	PathPattern *regexp.Regexp
	VulnType    string
	Reply       func(r *http.Request, payload string) (status int, body string, headers map[string]string)
}

type Session struct {
	IP               string
	RiskScore        int
	FirstSeen        time.Time
	LastSeen         time.Time
	CapturedPayloads []string
	Timeline         []models.AttackBeat
	mu               sync.Mutex
}

func New(cfg config.DeceptionConfig, bus *natsbus.Bus, log *slog.Logger) *Engine {
	e := &Engine{
		cfg:      cfg,
		bus:      bus,
		log:      log,
		sessions: map[string]*Session{},
		trusted:  parseCIDRs(cfg.TrustedProxies),
	}
	e.registerDecoys()
	if cfg.UpstreamURL != "" {
		if u, err := url.Parse(cfg.UpstreamURL); err == nil {
			e.proxy = httputil.NewSingleHostReverseProxy(u)
			e.proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
				http.Error(w, `{"error":"upstream unavailable"}`, http.StatusBadGateway)
			}
		}
	}

	cf := immunize.NewCloudflare(cfg.CloudflareToken, cfg.CloudflareZone, cfg.DryRun, log)
	aws := immunize.NewAWSWAF(context.Background(), cfg.AWSRegion, cfg.AWSIPSetID, cfg.AWSIPSetName, cfg.AWSCloudFront, cfg.DryRun, log)
	disp := immunize.NewMultiCloud(cf, aws, cfg.WAFWebhook, cfg.DryRun, log)
	e.reporter = NewThreatReporter(cfg.SIEMWebhook, bus, disp, cfg.DryRun, log)
	if cfg.AutoBlockScore > 0 {
		e.reporter.blockScore = cfg.AutoBlockScore
	}
	return e
}

func (e *Engine) Run(ctx context.Context) error {
	if !e.cfg.Enabled {
		e.log.Info("deception engine disabled")
		<-ctx.Done()
		return ctx.Err()
	}
	addr := e.cfg.ListenAddr
	if addr == "" {
		addr = ":8443"
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           e,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      45 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		e.log.Info("deception engine listening",
			"addr", addr,
			"upstream", e.cfg.UpstreamURL != "",
			"dry_run", e.cfg.DryRun,
		)
		errCh <- srv.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		sh, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sh)
		return ctx.Err()
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip, ipSrc := resolveClientIP(r, e.trusted)
	session := e.getOrCreateSession(ip)

	bodyBytes, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	payload := string(bodyBytes) + " " + r.URL.RawQuery + " " + r.Header.Get("User-Agent")

	w.Header().Set("Server", "Apache-Coyote/1.1")
	w.Header().Set("X-Powered-By", "Spring Boot 2.7.18; Log4j 2.14.1")
	w.Header().Set("X-Application-Context", "prod-api:8080")

	for _, decoy := range e.decoys {
		if decoy.PathPattern.MatchString(r.URL.Path) || decoy.PathPattern.MatchString(payload) {
			now := time.Now().UTC()
			session.mu.Lock()
			delta := int64(0)
			if !session.LastSeen.IsZero() {
				delta = now.Sub(session.LastSeen).Milliseconds()
			}
			session.RiskScore += 25
			session.LastSeen = now
			if len(session.CapturedPayloads) < 64 {
				session.CapturedPayloads = append(session.CapturedPayloads, truncate(payload, 512))
			}
			session.Timeline = append(session.Timeline, models.AttackBeat{
				At: now, Path: r.URL.Path, VulnClass: decoy.VulnType, DeltaMS: delta,
			})
			if len(session.Timeline) > 128 {
				session.Timeline = session.Timeline[len(session.Timeline)-128:]
			}
			score := session.RiskScore
			timeline := append([]models.AttackBeat(nil), session.Timeline...)
			session.mu.Unlock()

			e.log.Warn("deception intercept",
				"ip", ip, "ip_source", ipSrc, "vuln", decoy.VulnType, "path", r.URL.Path, "score", score,
			)

			evt := e.buildAttackEvent(ip, ipSrc, decoy, r, payload, score, timeline)
			e.reporter.RecordAndDispatch(evt)

			if score > 50 {
				time.Sleep(adaptiveDelay(score, e.cfg.MaxDelay))
			}

			status, body, headers := decoy.Reply(r, payload)
			for k, v := range headers {
				w.Header().Set(k, v)
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
			return
		}
	}

	if looksScanner(r, payload) {
		session.mu.Lock()
		session.RiskScore += 10
		session.mu.Unlock()
	}

	if e.proxy != nil && session.RiskScore < e.cfg.DecoyThreshold {
		e.proxy.ServeHTTP(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(notFoundHTML()))
}

func (e *Engine) buildAttackEvent(ip, ipSrc string, decoy Decoy, r *http.Request, payload string, score int, timeline []models.AttackBeat) models.AttackEvent {
	headers := map[string]string{}
	for _, k := range []string{
		"User-Agent", "Accept", "Accept-Language", "Content-Type", "Referer",
		"X-Forwarded-For", "CF-Connecting-IP", "True-Client-IP",
		"Cf-Ja3", "Cf-Ja4", "X-JA3", "X-JA4",
	} {
		if v := r.Header.Get(k); v != "" {
			headers[k] = v
		}
	}
	ja3 := firstHeader(r, "Cf-Ja3", "X-JA3", "JA3")
	ja4 := firstHeader(r, "Cf-Ja4", "X-JA4", "JA4")
	now := time.Now().UTC()
	return models.AttackEvent{
		ID:             "evt_atk_" + now.Format("20060102150405.000000"),
		Timestamp:      now,
		ClientIP:       ip,
		IPSource:       ipSrc,
		UserAgent:      r.UserAgent(),
		TargetEndpoint: r.URL.Path,
		Method:         r.Method,
		VulnClass:      decoy.VulnType,
		RawPayload:     truncate(payload, 4096),
		HTTPHeaders:    headers,
		JA3:            ja3,
		JA4:            ja4,
		ToolHint:       toolHint(r, payload),
		RiskScore:      score,
		Timeline:       timeline,
	}
}

func (e *Engine) getOrCreateSession(ip string) *Session {
	e.mu.Lock()
	defer e.mu.Unlock()
	s, ok := e.sessions[ip]
	if !ok {
		now := time.Now().UTC()
		s = &Session{IP: ip, FirstSeen: now, LastSeen: now}
		e.sessions[ip] = s
	}
	return s
}

func (e *Engine) registerDecoys() {
	e.decoys = []Decoy{
		{Name: "rce_debug", PathPattern: regexp.MustCompile(`(?i)/(api/v1/debug|exec|cmd|shell|console/v2)`), VulnType: "Command Injection (RCE)", Reply: replyRCE},
		{Name: "sqli_login", PathPattern: regexp.MustCompile(`(?i)/(admin/login|api/users|db/query)`), VulnType: "SQL Injection", Reply: replySQLi},
		{Name: "actuator", PathPattern: regexp.MustCompile(`(?i)/(actuator|jolokia|heapdump|env)`), VulnType: "Spring Actuator Exposure", Reply: replyActuator},
		{Name: "dotenv", PathPattern: regexp.MustCompile(`(?i)/\.env|/config\.json|/secrets`), VulnType: "Secret Exposure", Reply: replyDotEnv},
		{Name: "log4j_probe", PathPattern: regexp.MustCompile(`(?i)\$\{jndi:(ldap|rmi|dns)`), VulnType: "Log4Shell Probe", Reply: replyLog4j},
		{Name: "struts_probe", PathPattern: regexp.MustCompile(`(?i)(%\{|#cmd|action:|redirect:)`), VulnType: "Struts OGNL Probe", Reply: replyStruts},
		{Name: "stack_trace", PathPattern: regexp.MustCompile(`(?i)/(api/v1/crash|api/v1/render|graphql|internal/debug)`), VulnType: "Verbose Error Leak", Reply: replyStackOnMalformed},
	}
}

func replyRCE(_ *http.Request, payload string) (int, string, map[string]string) {
	headers := map[string]string{"Content-Type": "text/plain; charset=utf-8", "X-Debug-Node": "k8s-node-prod-04.internal"}
	p := strings.ToLower(payload)
	switch {
	case strings.Contains(p, "id") || strings.Contains(p, "whoami"):
		return 200, "uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:init_t:s0\n", headers
	case strings.Contains(p, "passwd") || strings.Contains(p, "cat /etc"):
		return 200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n", headers
	default:
		return 200, fmt.Sprintf("sh: 1: %s: Permission denied (SELinux enforcing)\n", fakeCmd(payload)), headers
	}
}

func replySQLi(_ *http.Request, payload string) (int, string, map[string]string) {
	headers := map[string]string{"Content-Type": "application/json", "X-Powered-By": "Express/4.17.1"}
	p := strings.ToUpper(payload)
	if strings.Contains(p, "UNION") || strings.Contains(p, "OR 1=1") || strings.Contains(p, "SLEEP") || strings.Contains(p, "WAITFOR") {
		time.Sleep(2 * time.Second)
		return 200, `{"status":"success","data":[{"id":1,"username":"admin","hash":"$2a$12$e8Y4vN1nSyntheticHoneyHash","role":"superadmin"}]}`, headers
	}
	return 401, `{"error":"Invalid database syntax near token 'WHERE'","code":1064}`, headers
}

func replyActuator(r *http.Request, _ string) (int, string, map[string]string) {
	headers := map[string]string{"Content-Type": "application/vnd.spring-boot.actuator.v2+json"}
	path := strings.ToLower(r.URL.Path)
	if strings.Contains(path, "heapdump") {
		return 200, "JAVA PROFILE 1.0.1" + strings.Repeat("\x00HONEY", 32), map[string]string{
			"Content-Type": "application/octet-stream", "Content-Disposition": "attachment; filename=heapdump.hprof",
		}
	}
	if strings.Contains(path, "env") {
		return 200, `{"activeProfiles":["prod"],"propertySources":[{"name":"systemEnvironment","properties":{"NATS_URL":{"value":"nats://honeypot-internal:4222"},"AWS_ACCESS_KEY_ID":{"value":"AKIA_HONEY_EXAMPLE"}}}]}`, headers
	}
	return 200, `{"_links":{"self":{"href":"/actuator"},"health":{"href":"/actuator/health"},"env":{"href":"/actuator/env"},"heapdump":{"href":"/actuator/heapdump"}}}`, headers
}

func replyDotEnv(_ *http.Request, _ string) (int, string, map[string]string) {
	return 200, "APP_ENV=production\nDB_HOST=db-prod.internal\nDB_PASSWORD=HoneyTrap!NotReal\nJWT_SECRET=" + generateFakeToken() + "\nAWS_SECRET_ACCESS_KEY=honey/synthetic/key\nTELEGRAM_BOT_TOKEN=0000000000:FAKE_HONEY_TOKEN_DO_NOT_USE\n",
		map[string]string{"Content-Type": "text/plain"}
}

func replyLog4j(_ *http.Request, payload string) (int, string, map[string]string) {
	return 500, fmt.Sprintf("java.lang.IllegalStateException: Error looking up JNDI resource [%s]\n\tat org.apache.logging.log4j.core.net.JndiManager.lookup(JndiManager.java:172)\n\tat com.acme.api.AuthFilter.doFilter(AuthFilter.java:88)\n", truncate(payload, 80)),
		map[string]string{"Content-Type": "text/plain", "X-Log4j": "2.14.1"}
}

func replyStruts(_ *http.Request, _ string) (int, string, map[string]string) {
	return 500, `<html><head><title>Apache Tomcat/8.5.32 - Error report</title></head><body><h1>HTTP Status 500</h1><pre>ognl.OgnlException: target is null for setProperty(null, "multipartMaxSize")
	at com.opensymphony.xwork2.ognl.OgnlUtil.setValue(OgnlUtil.java:234)
	at org.apache.struts2.dispatcher.Dispatcher.serviceAction(Dispatcher.java:501)
</pre><!-- debug buildId=prod-struts-honeypot --></body></html>`, map[string]string{"Content-Type": "text/html"}
}

func replyStackOnMalformed(r *http.Request, payload string) (int, string, map[string]string) {
	if !strings.ContainsAny(payload, `'";{}<>`) && r.Method == http.MethodGet {
		return 404, `{"error":"Resource not found"}`, map[string]string{"Content-Type": "application/json"}
	}
	return 500, `Traceback (most recent call last):
  File "/opt/acme/api/app.py", line 214, in dispatch
    return handler(request)
  File "/opt/acme/api/views/user.py", line 91, in detail
    obj = queryset.get(pk=request.GET['id'])
ValueError: invalid literal for int() with base 10: ` + truncate(payload, 40) + `
`, map[string]string{"Content-Type": "text/plain"}
}

func adaptiveDelay(score int, maxDelay time.Duration) time.Duration {
	if maxDelay <= 0 {
		maxDelay = 15 * time.Second
	}
	base := int64(500)
	mult := int64(score / 25)
	if mult < 1 {
		mult = 1
	}
	nBig, _ := rand.Int(rand.Reader, big.NewInt(300))
	total := time.Duration(base*mult+nBig.Int64()) * time.Millisecond
	if total > maxDelay {
		return maxDelay
	}
	return total
}

func looksScanner(r *http.Request, payload string) bool {
	return toolHint(r, payload) != ""
}

func toolHint(r *http.Request, payload string) string {
	ua := strings.ToLower(r.UserAgent())
	blob := strings.ToLower(payload)
	needles := []string{"nikto", "sqlmap", "nmap", "masscan", "zgrab", "dirbuster", "gobuster", "ffuf", "nuclei", "metasploit", "curl/", "python-requests"}
	for _, n := range needles {
		if strings.Contains(ua, n) || strings.Contains(blob, n) {
			return n
		}
	}
	return ""
}

func notFoundHTML() string {
	tok := generateFakeToken()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"honey-admin","iss":"decoy.internal","aud":"honeypot"}`))
	fakeJWT := header + "." + body + "." + tok[:16]
	return fmt.Sprintf(`<!doctype html><html><head><title>404</title></head><body><h1>Not Found</h1><!-- TODO: rotate jwt %s before prod cutover --><script>window.__CFG={api:"/api/v1",debug:true}</script></body></html>`, fakeJWT)
}

func generateFakeToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func fakeCmd(payload string) string {
	fields := strings.Fields(payload)
	if len(fields) == 0 {
		return "cmd"
	}
	return truncate(fields[0], 40)
}

// resolveClientIP prefers edge-verified headers only when the peer is a trusted proxy.
func resolveClientIP(r *http.Request, trusted []*net.IPNet) (ip, source string) {
	peer := peerIP(r.RemoteAddr)
	peerTrusted := isTrusted(peer, trusted) || len(trusted) == 0 && peerIsPrivate(peer)

	if peerTrusted {
		if v := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); v != "" && net.ParseIP(v) != nil {
			return v, "cf-connecting-ip"
		}
		if v := strings.TrimSpace(r.Header.Get("True-Client-IP")); v != "" && net.ParseIP(v) != nil {
			return v, "true-client-ip"
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			cand := strings.TrimSpace(parts[0])
			if net.ParseIP(cand) != nil {
				return cand, "xff"
			}
		}
	}
	return peer, "remote_addr"
}

func peerIP(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return remote
	}
	return host
}

func peerIsPrivate(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && (p.IsLoopback() || p.IsPrivate())
}

func isTrusted(ip string, nets []*net.IPNet) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(p) {
			return true
		}
	}
	return false
}

func parseCIDRs(list []string) []*net.IPNet {
	var out []*net.IPNet
	for _, c := range list {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !strings.Contains(c, "/") {
			if ip := net.ParseIP(c); ip != nil {
				if ip.To4() != nil {
					c += "/32"
				} else {
					c += "/128"
				}
			}
		}
		_, n, err := net.ParseCIDR(c)
		if err == nil {
			out = append(out, n)
		}
	}
	return out
}

func firstHeader(r *http.Request, keys ...string) string {
	for _, k := range keys {
		if v := r.Header.Get(k); v != "" {
			return v
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}