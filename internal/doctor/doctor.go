package doctor

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/theworker02/ATDE/v2/internal/config"
)

// Check is one preflight result.
type Check struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Detail  string `json:"detail"`
	Hint    string `json:"hint,omitempty"`
	Level   string `json:"level"` // info|warn|fail
}

// Run executes local readiness checks (no mutation).
func Run(cfg *config.Config) []Check {
	var out []Check
	out = append(out, checkGo())
	out = append(out, checkDirs()...)
	if cfg != nil {
		out = append(out, checkConfig(cfg)...)
		out = append(out, checkNATS(cfg.NATS.URL))
		out = append(out, checkPorts(cfg)...)
		out = append(out, checkFirewallTools(cfg)...)
		out = append(out, checkCloudKeys(cfg)...)
	}
	return out
}

func checkGo() Check {
	return Check{
		Name: "go_runtime", OK: true, Level: "info",
		Detail: fmt.Sprintf("%s %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH),
	}
}

func checkDirs() []Check {
	var out []Check
	for _, d := range []string{"./data", "./data/caught", "./data/evidence", "./data/sandbox"} {
		err := os.MkdirAll(d, 0o750)
		ok := err == nil
		c := Check{Name: "dir:" + d, OK: ok, Level: "fail"}
		if ok {
			c.Level = "info"
			c.Detail = "writable"
		} else {
			c.Detail = err.Error()
			c.Hint = "create the directory or fix permissions"
		}
		out = append(out, c)
	}
	return out
}

func checkConfig(cfg *config.Config) []Check {
	live := cfg.App.Live && !cfg.App.DryRun
	c := Check{
		Name: "mode", OK: true, Level: "info",
		Detail: fmt.Sprintf("live=%v dry_run=%v local_fw=%v ops=%s",
			cfg.App.Live, cfg.App.DryRun, cfg.ActiveDefense.Edge.LocalFirewall, cfg.App.OpsAddr),
	}
	if !live {
		c.Level = "warn"
		c.Hint = "set ATDE_LIVE=1 (and dry_run false) for real containment"
	}
	return []Check{c}
}

func checkNATS(url string) Check {
	url = strings.TrimSpace(url)
	if url == "" {
		return Check{Name: "nats", OK: false, Level: "fail", Detail: "NATS_URL empty", Hint: "docker compose up -d nats"}
	}
	host := url
	host = strings.TrimPrefix(host, "nats://")
	host = strings.TrimPrefix(host, "tls://")
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	if !strings.Contains(host, ":") {
		host += ":4222"
	}
	conn, err := net.DialTimeout("tcp", host, 2*time.Second)
	if err != nil {
		return Check{Name: "nats", OK: false, Level: "fail", Detail: err.Error(), Hint: "make nats / docker compose up -d nats"}
	}
	_ = conn.Close()
	return Check{Name: "nats", OK: true, Level: "info", Detail: "reachable " + host}
}

func checkPorts(cfg *config.Config) []Check {
	addrs := []struct{ name, addr string }{
		{"honeypot_http", cfg.Ingest.Honeypot.HTTPAddr},
		{"honeypot_ssh", cfg.Ingest.Honeypot.SSHAddr},
		{"deception", cfg.Deception.ListenAddr},
		{"ops", cfg.App.OpsAddr},
	}
	var out []Check
	for _, a := range addrs {
		if a.addr == "" || a.addr == "off" {
			continue
		}
		ln, err := net.Listen("tcp", a.addr)
		if err != nil {
			out = append(out, Check{
				Name: "bind:" + a.name, OK: false, Level: "warn",
				Detail: err.Error(), Hint: "port in use or permission denied — may already be ATDE",
			})
			continue
		}
		_ = ln.Close()
		out = append(out, Check{Name: "bind:" + a.name, OK: true, Level: "info", Detail: a.addr + " free"})
	}
	return out
}

func checkFirewallTools(cfg *config.Config) []Check {
	if cfg == nil || !cfg.ActiveDefense.Edge.LocalFirewall {
		return []Check{{Name: "local_firewall", OK: true, Level: "info", Detail: "disabled"}}
	}
	var bin string
	switch runtime.GOOS {
	case "windows":
		bin = "netsh"
	default:
		bin = "ipset"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return []Check{{
			Name: "local_firewall", OK: false, Level: "warn",
			Detail: bin + " not found", Hint: "install ipset/iptables (Linux) or run as admin (Windows netsh)",
		}}
	}
	return []Check{{Name: "local_firewall", OK: true, Level: "info", Detail: path}}
}

func checkCloudKeys(cfg *config.Config) []Check {
	var out []Check
	cf := os.Getenv("CLOUDFLARE_API_TOKEN") != "" || cfg.ActiveDefense.Edge.CloudflareToken != ""
	out = append(out, Check{
		Name: "cloudflare", OK: true, Level: "info",
		Detail: boolStr(cf, "credentials present", "not configured (optional)"),
	})
	aws := os.Getenv("AWS_ACCESS_KEY_ID") != "" || cfg.ActiveDefense.Edge.AWSIPSetID != ""
	out = append(out, Check{
		Name: "aws_waf", OK: true, Level: "info",
		Detail: boolStr(aws, "credentials/config present", "not configured (optional)"),
	})
	wh := os.Getenv("ATDE_WEBHOOK_URL")
	out = append(out, Check{
		Name: "webhook", OK: true, Level: "info",
		Detail: boolStr(wh != "", "ATDE_WEBHOOK_URL set", "not configured (optional)"),
	})
	alert := os.Getenv("ATDE_ALERT_TO") != "" || os.Getenv("ATDE_ALERT_EMAIL") != "" || os.Getenv("ATDE_OWNER_EMAIL") != ""
	smtpOK := os.Getenv("ATDE_SMTP_HOST") != ""
	pgpOK := os.Getenv("ATDE_PGP_PUBLIC_KEY_FILE") != "" || os.Getenv("ATDE_PGP_PUBLIC_KEY") != ""
	switch {
	case alert && smtpOK && pgpOK:
		out = append(out, Check{Name: "email_alerts", OK: true, Level: "info", Detail: "SMTP + PGP configured"})
	case alert && smtpOK:
		out = append(out, Check{Name: "email_alerts", OK: true, Level: "warn", Detail: "SMTP set but no PGP key — emails may be plaintext", Hint: "set ATDE_PGP_PUBLIC_KEY_FILE and ATDE_PGP_REQUIRE=1"})
	case alert:
		out = append(out, Check{Name: "email_alerts", OK: false, Level: "warn", Detail: "ATDE_ALERT_TO set but ATDE_SMTP_HOST missing"})
	default:
		out = append(out, Check{Name: "email_alerts", OK: true, Level: "info", Detail: "not configured (optional)"})
	}
	// Soft probe ops if already running
	ops := cfg.App.OpsAddr
	if ops != "" && ops != "off" {
		host := ops
		if strings.HasPrefix(host, ":") {
			host = "127.0.0.1" + host
		}
		client := &http.Client{Timeout: 800 * time.Millisecond}
		resp, err := client.Get("http://" + host + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			out = append(out, Check{Name: "ops_live", OK: true, Level: "info", Detail: "ATDE already answering on " + ops})
		}
	}
	return out
}

func boolStr(v bool, yes, no string) string {
	if v {
		return yes
	}
	return no
}

// ExitCode returns 0 if no fail-level checks, else 1.
func ExitCode(checks []Check) int {
	for _, c := range checks {
		if !c.OK && c.Level == "fail" {
			return 1
		}
	}
	return 0
}
