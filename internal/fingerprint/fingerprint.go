package fingerprint

import (
	"net/http"
	"strings"
)

// Result classifies an interaction for dossiers and the operator console.
type Result struct {
	Tool       string   `json:"tool,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	Severity   int      `json:"severity"` // 1–100
	Summary    string   `json:"summary,omitempty"`
	Techniques []string `json:"techniques,omitempty"` // MITRE ATT&CK
}

// FromHTTP fingerprints a request from path, UA, and optional body.
func FromHTTP(r *http.Request, body string) Result {
	path := strings.ToLower(r.URL.Path)
	ua := strings.ToLower(r.UserAgent())
	q := strings.ToLower(r.URL.RawQuery)
	bodyL := strings.ToLower(body)
	var tags []string
	tool := "unknown"
	sev := 15
	summary := "http probe"

	switch {
	case strings.Contains(ua, "masscan"):
		tool, sev, summary = "masscan", 25, "masscan probe"
	case strings.Contains(ua, "zgrab") || strings.Contains(ua, "zmap"):
		tool, sev, summary = "zgrab", 30, "zgrab/zmap probe"
	case strings.Contains(ua, "nuclei"):
		tool, sev, summary = "nuclei", 55, "nuclei scanner"
	case strings.Contains(ua, "sqlmap"):
		tool, sev, summary = "sqlmap", 80, "sqlmap injection attempt"
	case strings.Contains(ua, "nikto"):
		tool, sev, summary = "nikto", 50, "nikto web scan"
	case strings.Contains(ua, "nmap") || strings.Contains(ua, "npcap"):
		tool, sev, summary = "nmap", 35, "nmap http probe"
	case strings.Contains(ua, "curl/") || strings.Contains(ua, "wget/") || strings.Contains(ua, "python-requests") || strings.Contains(ua, "go-http-client") || strings.Contains(ua, "httpx"):
		tool, sev, summary = "scripted-http", 20, "scripted HTTP client"
	case strings.Contains(ua, "mozilla") || strings.Contains(ua, "chrome") || strings.Contains(ua, "firefox"):
		tool, sev, summary = "browser", 20, "browser-like client"
	}

	add := func(t string) {
		for _, x := range tags {
			if x == t {
				return
			}
		}
		tags = append(tags, t)
	}

	switch {
	case strings.Contains(path, "wp-login") || strings.Contains(path, "xmlrpc"):
		add("wordpress"); sev = max(sev, 40); summary = "WordPress auth surface"
	case path == "/login" || path == "/mfa" || strings.HasPrefix(path, "/admin"):
		add("auth-burn"); sev = max(sev, 45); summary = "credential / MFA burn"
	case strings.Contains(path, ".env") || strings.Contains(path, ".git") || strings.Contains(path, "phpinfo") || strings.Contains(path, "_profiler") || strings.Contains(path, "/backup"):
		add("vuln-bait"); sev = max(sev, 60); summary = "juicy-file / vuln bait"
	case strings.Contains(path, "debug") || strings.Contains(q, "cmd=") || strings.Contains(bodyL, "cmd="):
		add("rce-bait"); sev = max(sev, 70); summary = "synthetic RCE canary"
	case strings.Contains(path, "openapi") || strings.Contains(path, "swagger") || path == "/robots.txt":
		add("recon"); sev = max(sev, 20); summary = "API / recon surface"
	case strings.HasPrefix(path, "/api/"):
		add("api"); sev = max(sev, 35); summary = "API probe"
	}

	if strings.Contains(bodyL, "' or") || strings.Contains(bodyL, "union select") || strings.Contains(q, "union+select") {
		add("sqli"); tool = prefer(tool, "sqlmap"); sev = max(sev, 85); summary = "SQL injection payload"
	}
	if strings.Contains(bodyL, "<script") || strings.Contains(q, "%3cscript") {
		add("xss"); sev = max(sev, 50); summary = "XSS-like payload"
	}
	if strings.Contains(bodyL, "password=") || strings.Contains(bodyL, "passwd=") || r.Method == http.MethodPost && (path == "/login" || strings.Contains(path, "wp-login")) {
		add("cred-spray"); sev = max(sev, 55); summary = "credential attempt"
	}

	res := Result{Tool: tool, Tags: tags, Severity: sev, Summary: summary}
	res.Techniques = TechniquesFor(tags, path, tool)
	return res
}

// FromService fingerprints non-HTTP bait (ssh, redis, telnet).
func FromService(service, username, payload string) Result {
	sev := 40
	tags := []string{}
	tool := "unknown"
	summary := service + " probe"
	switch {
	case strings.Contains(service, "ssh"):
		tags = append(tags, "ssh-auth-burn", "cred-spray")
		sev = 65
		summary = "SSH password burn"
		if username != "" {
			summary = "SSH auth as " + username
		}
	case strings.Contains(service, "redis"):
		tags = append(tags, "redis-bait")
		sev = 70
		summary = "Redis protocol bait"
		pl := strings.ToUpper(payload)
		if strings.Contains(pl, "CONFIG") || strings.Contains(pl, "SLAVEOF") || strings.Contains(pl, "MODULE") {
			tags = append(tags, "redis-exploit")
			sev = 90
			summary = "Redis exploit-oriented command"
		}
	case strings.Contains(service, "telnet"):
		tags = append(tags, "telnet-bait", "iot-botnet")
		sev = 60
		summary = "Telnet login bait"
	case strings.Contains(service, "mysql"):
		tags = append(tags, "mysql-bait", "db-scan")
		sev = 75
		tool = "mysql-scanner"
		summary = "MySQL greeting / auth bait"
		if strings.Contains(strings.ToLower(payload), "root") {
			sev = 85
			summary = "MySQL root auth attempt"
		}
	case strings.Contains(service, "ftp"):
		tags = append(tags, "ftp-bait", "cred-spray")
		sev = 55
		tool = "ftp-scanner"
		summary = "FTP login bait"
		if username != "" {
			summary = "FTP auth as " + username
		}
	case strings.Contains(service, "smtp"):
		tags = append(tags, "smtp-bait", "cred-spray")
		sev = 50
		tool = "smtp-scanner"
		summary = "SMTP auth bait"
	case strings.Contains(service, "mongo"):
		tags = append(tags, "mongo-bait", "db-scan")
		sev = 80
		tool = "mongo-scanner"
		summary = "MongoDB unauth probe bait"
	case strings.Contains(service, "elastic"):
		tags = append(tags, "elastic-bait", "db-scan")
		sev = 75
		tool = "es-scanner"
		summary = "Elasticsearch probe bait"
	}
	res := Result{Tool: tool, Tags: tags, Severity: sev, Summary: summary}
	res.Techniques = TechniquesFor(tags, service, tool)
	return res
}

func prefer(cur, next string) string {
	if cur == "" || cur == "unknown" || cur == "scripted-http" || cur == "browser" {
		return next
	}
	return cur
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
