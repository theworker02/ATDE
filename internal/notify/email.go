package notify

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/gopenpgp/v3/crypto"

	"github.com/theworker02/blind-botnet/internal/catch"
)

// EmailConfig controls SMTP alerts to the catch-node owner.
type EmailConfig struct {
	To           string
	From         string
	Host         string
	Port         string
	Username     string
	Password     string
	TLSMode      string // starttls | tls | none
	PGPKeyFile   string
	PGPKeyArmored string
	RequirePGP   bool
	MinSeverity  int
	Cooldown      time.Duration
	NodeName     string
	ConsoleURL   string
}

// Email sends TLS-protected SMTP messages; body is PGP-encrypted when a public key is configured.
type Email struct {
	cfg    EmailConfig
	log    *slog.Logger
	pubKey *crypto.Key
	mu     sync.Mutex
	last   map[string]time.Time
}

// EmailFromEnv builds config from ATDE_* environment variables. Returns nil if not configured.
func EmailFromEnv(log *slog.Logger) (*Email, error) {
	to := strings.TrimSpace(firstNonEmpty(os.Getenv("ATDE_ALERT_TO"), os.Getenv("ATDE_ALERT_EMAIL"), os.Getenv("ATDE_OWNER_EMAIL")))
	host := strings.TrimSpace(os.Getenv("ATDE_SMTP_HOST"))
	if to == "" || host == "" {
		return nil, nil
	}
	cfg := EmailConfig{
		To:            to,
		From:          firstNonEmpty(os.Getenv("ATDE_ALERT_FROM"), os.Getenv("ATDE_SMTP_FROM"), to),
		Host:          host,
		Port:          firstNonEmpty(os.Getenv("ATDE_SMTP_PORT"), "587"),
		Username:      os.Getenv("ATDE_SMTP_USER"),
		Password:      os.Getenv("ATDE_SMTP_PASS"),
		TLSMode:       strings.ToLower(firstNonEmpty(os.Getenv("ATDE_SMTP_TLS"), "starttls")),
		PGPKeyFile:    os.Getenv("ATDE_PGP_PUBLIC_KEY_FILE"),
		PGPKeyArmored: os.Getenv("ATDE_PGP_PUBLIC_KEY"),
		RequirePGP:    truthy(os.Getenv("ATDE_PGP_REQUIRE")),
		MinSeverity:   40,
		Cooldown:      15 * time.Minute,
		NodeName:      firstNonEmpty(os.Getenv("ATDE_NODE_NAME"), "atde-catch-node"),
		ConsoleURL:    strings.TrimSpace(os.Getenv("ATDE_CONSOLE_URL")),
	}
	if v := os.Getenv("ATDE_ALERT_MIN_SEVERITY"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.MinSeverity)
	}
	if v := os.Getenv("ATDE_ALERT_COOLDOWN"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Cooldown = d
		}
	}
	return NewEmail(cfg, log)
}

func NewEmail(cfg EmailConfig, log *slog.Logger) (*Email, error) {
	if log == nil {
		log = slog.Default()
	}
	e := &Email{cfg: cfg, log: log, last: map[string]time.Time{}}
	armored := strings.TrimSpace(cfg.PGPKeyArmored)
	if armored == "" && cfg.PGPKeyFile != "" {
		raw, err := os.ReadFile(cfg.PGPKeyFile)
		if err != nil {
			return nil, fmt.Errorf("pgp key file: %w", err)
		}
		armored = string(raw)
	}
	if armored != "" {
		key, err := crypto.NewKeyFromArmored(armored)
		if err != nil {
			return nil, fmt.Errorf("pgp public key: %w", err)
		}
		e.pubKey = key
	}
	if cfg.RequirePGP && e.pubKey == nil {
		return nil, fmt.Errorf("ATDE_PGP_REQUIRE set but no public key configured")
	}
	return e, nil
}

// Handle implements catch.OnRecord — emails the owner about recorded attackers.
func (e *Email) Handle(r catch.Record) {
	if e == nil {
		return
	}
	if r.Severity > 0 && r.Severity < e.cfg.MinSeverity {
		return
	}
	// Always notify on blocks / auth burns even if severity field missing on older records.
	if r.Severity == 0 && !containsAny(r.Actions, "auth_burn", "local_firewall") &&
		!strings.Contains(r.Service, "login") && !strings.Contains(r.Service, "ssh") &&
		!strings.Contains(r.Service, "redis") && !strings.Contains(r.Service, "telnet") {
		return
	}
	if !e.allow(r.IP) {
		return
	}
	if err := e.SendAttackAlert(r); err != nil {
		e.log.Warn("alert email failed", "err", err, "ip", r.IP)
	}
}

func (e *Email) allow(ip string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	if t, ok := e.last[ip]; ok && now.Sub(t) < e.cfg.Cooldown {
		return false
	}
	e.last[ip] = now
	return true
}

// SendBootAlert notifies the owner that the catch-node is live.
func (e *Email) SendBootAlert() error {
	if e == nil {
		return nil
	}
	plain := fmt.Sprintf(`ATDE catch-node online

Node: %s
Time: %s UTC

Your decoy surfaces are live. When scanners or attackers interact with them,
ATDE will record the activity under data/caught/ and email you (this address)
with encrypted details when configured.

Console: %s

— ATDE autonomous catcher
`, e.cfg.NodeName, time.Now().UTC().Format(time.RFC3339), e.consoleURL())
	subj := fmt.Sprintf("[ATDE] %s deployed — attack recording armed", e.cfg.NodeName)
	return e.send(subj, plain)
}

// SendAttackAlert emails a recorded attack report.
func (e *Email) SendAttackAlert(r catch.Record) error {
	plain := formatAttackPlain(r, e.cfg.NodeName, e.consoleURL())
	subj := "[ATDE] Attacker recorded — open encrypted body"
	if e.pubKey == nil {
		subj = fmt.Sprintf("[ATDE] Attacker recorded: %s", r.IP)
	}
	return e.send(subj, plain)
}

func (e *Email) consoleURL() string {
	if e.cfg.ConsoleURL != "" {
		return e.cfg.ConsoleURL
	}
	return "http://YOUR_IP:9091/console"
}

func (e *Email) send(subject, plaintext string) error {
	body := plaintext
	encrypted := false
	if e.pubKey != nil {
		armored, err := encryptPGP(e.pubKey, plaintext)
		if err != nil {
			return err
		}
		body = armored
		encrypted = true
	} else {
		if e.cfg.RequirePGP {
			return fmt.Errorf("refusing plaintext alert: PGP required")
		}
		e.log.Warn("alert email sending WITHOUT PGP encryption — set ATDE_PGP_PUBLIC_KEY_FILE")
	}

	var msg bytes.Buffer
	fmt.Fprintf(&msg, "From: %s\r\n", sanitizeHeader(e.cfg.From))
	fmt.Fprintf(&msg, "To: %s\r\n", sanitizeHeader(e.cfg.To))
	fmt.Fprintf(&msg, "Subject: %s\r\n", sanitizeHeader(subject))
	fmt.Fprintf(&msg, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&msg, "X-Mailer: ATDE-notify/0.1\r\n")
	fmt.Fprintf(&msg, "Content-Type: text/plain; charset=utf-8\r\n")
	if encrypted {
		fmt.Fprintf(&msg, "X-ATDE-Encrypted: openpgp\r\n")
	}
	msg.WriteString("\r\n")
	msg.WriteString(body)
	if !strings.HasSuffix(body, "\n") {
		msg.WriteString("\r\n")
	}

	addr := net.JoinHostPort(e.cfg.Host, e.cfg.Port)
	auth := smtp.Auth(nil)
	if e.cfg.Username != "" {
		auth = smtp.PlainAuth("", e.cfg.Username, e.cfg.Password, e.cfg.Host)
	}

	switch e.cfg.TLSMode {
	case "tls", "smtps":
		return sendTLS(addr, e.cfg.Host, auth, e.cfg.From, []string{e.cfg.To}, msg.Bytes())
	case "none":
		return smtp.SendMail(addr, auth, e.cfg.From, []string{e.cfg.To}, msg.Bytes())
	default: // starttls
		return sendStartTLS(addr, e.cfg.Host, auth, e.cfg.From, []string{e.cfg.To}, msg.Bytes())
	}
}

func encryptPGP(pub *crypto.Key, plaintext string) (string, error) {
	pgp := crypto.PGP()
	enc, err := pgp.Encryption().Recipient(pub).New()
	if err != nil {
		return "", err
	}
	pgpMsg, err := enc.Encrypt([]byte(plaintext))
	if err != nil {
		return "", err
	}
	armored, err := pgpMsg.ArmorBytes()
	if err != nil {
		return "", err
	}
	return string(armored), nil
}

func formatAttackPlain(r catch.Record, node, console string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ATDE attack recorded\n\n")
	fmt.Fprintf(&b, "An attacker interacted with your decoy host and HAS BEEN RECORDED.\n\n")
	fmt.Fprintf(&b, "Node:      %s\n", node)
	fmt.Fprintf(&b, "Caught at: %s\n", r.CaughtAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "IP:        %s\n", r.IP)
	fmt.Fprintf(&b, "Source:    %s\n", r.Source)
	fmt.Fprintf(&b, "Service:   %s\n", r.Service)
	fmt.Fprintf(&b, "Method:    %s\n", r.Method)
	fmt.Fprintf(&b, "Path:      %s\n", r.Path)
	fmt.Fprintf(&b, "Severity:  %d\n", r.Severity)
	fmt.Fprintf(&b, "Tool:      %s\n", r.Tool)
	fmt.Fprintf(&b, "Summary:   %s\n", r.Summary)
	fmt.Fprintf(&b, "Tags:      %s\n", strings.Join(r.Tags, ", "))
	fmt.Fprintf(&b, "Actions:   %s\n", strings.Join(r.Actions, ", "))
	fmt.Fprintf(&b, "Reason:    %s\n", r.Reason)
	fmt.Fprintf(&b, "UA:        %s\n", r.UserAgent)
	if snip := r.Meta["body_snippet"]; snip != "" {
		fmt.Fprintf(&b, "Snippet:   %s\n", truncate(snip, 400))
	}
	if u := r.Meta["username"]; u != "" {
		fmt.Fprintf(&b, "Username:  %s\n", u)
	}
	fmt.Fprintf(&b, "\nEvidence on node:\n")
	fmt.Fprintf(&b, "  data/caught/events.jsonl\n")
	fmt.Fprintf(&b, "  data/caught/dossier_%s.json\n", sanitizeIP(r.IP))
	fmt.Fprintf(&b, "\nConsole: %s\n", console)
	fmt.Fprintf(&b, "\nThis notification confirms the interaction was captured by ATDE.\n")
	fmt.Fprintf(&b, "— ATDE autonomous catcher\n")
	return b.String()
}

func sendStartTLS(addr, host string, auth smtp.Auth, from string, to []string, msg []byte) error {
	c, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); ok {
		cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
		if err := c.StartTLS(cfg); err != nil {
			return err
		}
	}
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	return writeMail(c, from, to, msg)
}

func sendTLS(addr, host string, auth smtp.Auth, from string, to []string, msg []byte) error {
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer c.Close()
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	return writeMail(c, from, to, msg)
}

func writeMail(c *smtp.Client, from string, to []string, msg []byte) error {
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func sanitizeHeader(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, s)
}

func sanitizeIP(ip string) string {
	return catch.Sanitize(ip)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func containsAny(ss []string, needles ...string) bool {
	for _, s := range ss {
		for _, n := range needles {
			if s == n {
				return true
			}
		}
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
