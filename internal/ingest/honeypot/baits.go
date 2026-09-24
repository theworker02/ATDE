package honeypot

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/theworker02/blind-botnet/v2/internal/catch"
	"github.com/theworker02/blind-botnet/v2/internal/fingerprint"
	"github.com/theworker02/blind-botnet/v2/internal/models"
)

func (s *Server) serveExtraBaits(done <-chan struct{}) {
	if s.cfg.RedisAddr != "" && s.cfg.RedisAddr != "off" {
		go s.serveRedis(done)
	}
	if s.cfg.TelnetAddr != "" && s.cfg.TelnetAddr != "off" {
		go s.serveTelnet(done)
	}
	if s.cfg.MySQLAddr != "" && s.cfg.MySQLAddr != "off" {
		go s.serveMySQL(done)
	}
	if s.cfg.FTPAddr != "" && s.cfg.FTPAddr != "off" {
		go s.serveFTP(done)
	}
	if s.cfg.SMTPAddr != "" && s.cfg.SMTPAddr != "off" {
		go s.serveSMTP(done)
	}
	if s.cfg.ESAddr != "" && s.cfg.ESAddr != "off" {
		go s.serveElastic(done)
	}
	if s.cfg.MongoAddr != "" && s.cfg.MongoAddr != "off" {
		go s.serveMongo(done)
	}
}

func (s *Server) serveRedis(done <-chan struct{}) {
	ln, err := net.Listen("tcp", s.cfg.RedisAddr)
	if err != nil {
		s.log.Warn("redis bait failed", "err", err)
		return
	}
	go func() {
		<-done
		_ = ln.Close()
	}()
	s.log.Info("honeypot redis bait listening", "addr", s.cfg.RedisAddr)
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-done:
				return
			default:
				continue
			}
		}
		go s.handleRedis(c)
	}
}

func (s *Server) handleRedis(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	ip := catch.StripPort(c.RemoteAddr().String())
	br := bufio.NewReader(c)
	var cmds []string
	for i := 0; i < 8; i++ {
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		cmds = append(cmds, line)
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "PING") || upper == "*1\r\n$4\r\nPING" || strings.Contains(upper, "PING"):
			_, _ = c.Write([]byte("+PONG\r\n"))
		case strings.Contains(upper, "INFO"):
			_, _ = fmt.Fprintf(c, "$%d\r\n%s\r\n", len(redisInfo()), redisInfo())
		case strings.Contains(upper, "AUTH"):
			_, _ = c.Write([]byte("-WRONGPASS invalid username-password pair\r\n"))
		case strings.Contains(upper, "CONFIG") || strings.Contains(upper, "SLAVEOF") || strings.Contains(upper, "MODULE"):
			_, _ = c.Write([]byte("-ERR unknown command\r\n"))
		default:
			_, _ = c.Write([]byte("-ERR unknown command\r\n"))
		}
	}
	payload := strings.Join(cmds, " | ")
	fp := fingerprint.FromService("redis-bait", "", payload)
	s.recordServiceHit(ip, "redis-bait", "/redis", payload, fp)
}

func redisInfo() string {
	return "redis_version:7.2.4\r\nredis_mode:standalone\r\nos:Linux 5.15.0 x86_64\r\ntcp_port:6379\r\n# ATDE canary — no real Redis\r\n"
}

func (s *Server) serveTelnet(done <-chan struct{}) {
	ln, err := net.Listen("tcp", s.cfg.TelnetAddr)
	if err != nil {
		s.log.Warn("telnet bait failed", "err", err)
		return
	}
	go func() {
		<-done
		_ = ln.Close()
	}()
	s.log.Info("honeypot telnet bait listening", "addr", s.cfg.TelnetAddr)
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-done:
				return
			default:
				continue
			}
		}
		go s.handleTelnet(c)
	}
}

func (s *Server) handleTelnet(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(45 * time.Second))
	ip := catch.StripPort(c.RemoteAddr().String())
	br := bufio.NewReader(c)
	_, _ = fmt.Fprintf(c, "\r\n%s login: ", s.site.HostHint)
	user, _ := br.ReadString('\n')
	user = strings.TrimSpace(user)
	time.Sleep(200 * time.Millisecond)
	_, _ = fmt.Fprintf(c, "Password: ")
	pass, _ := br.ReadString('\n')
	pass = strings.TrimSpace(pass)
	time.Sleep(600 * time.Millisecond)
	_, _ = fmt.Fprintf(c, "\r\nLogin incorrect\r\n")
	fp := fingerprint.FromService("telnet-bait", user, pass)
	raw, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	s.recordServiceHit(ip, "telnet-bait", "/telnet", string(raw), fp)
}

func (s *Server) serveMySQL(done <-chan struct{}) {
	ln, err := net.Listen("tcp", s.cfg.MySQLAddr)
	if err != nil {
		s.log.Warn("mysql bait failed", "err", err)
		return
	}
	go func() {
		<-done
		_ = ln.Close()
	}()
	s.log.Info("honeypot mysql bait listening", "addr", s.cfg.MySQLAddr)
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-done:
				return
			default:
				continue
			}
		}
		go s.handleMySQL(c)
	}
}

func (s *Server) handleMySQL(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	ip := catch.StripPort(c.RemoteAddr().String())
	// Minimal MySQL protocol handshake (greeting) — enough for scanners to bite.
	greeting := mysqlGreeting()
	if _, err := c.Write(greeting); err != nil {
		return
	}
	buf := make([]byte, 256)
	n, _ := c.Read(buf)
	payload := base64.StdEncoding.EncodeToString(buf[:n])
	userHint := "unknown"
	if n > 36 {
		// Auth packet often has username after fixed header; best-effort extract.
		rest := buf[36:n]
		if i := strings.IndexByte(string(rest), 0); i > 0 {
			userHint = string(rest[:i])
		}
	}
	// Error packet: Access denied
	_, _ = c.Write(mysqlAccessDenied())
	fp := fingerprint.FromService("mysql-bait", userHint, payload)
	raw, _ := json.Marshal(map[string]string{"username": userHint, "auth_b64": payload})
	s.recordServiceHit(ip, "mysql-bait", "/mysql", string(raw), fp)
}

func mysqlGreeting() []byte {
	// Simplified Protocol::HandshakeV10-ish greeting with version string.
	ver := append([]byte("8.0.36-atde-canary"), 0)
	payload := make([]byte, 0, 64)
	payload = append(payload, 10) // protocol version
	payload = append(payload, ver...)
	payload = append(payload, 1, 0, 0, 0)             // connection id
	payload = append(payload, []byte("atdebait1")...) // auth plugin data part1 (8)
	payload = append(payload, 0)                      // filler
	payload = append(payload, 0xFF, 0xF7)             // capability flags lower
	payload = append(payload, 33)                     // charset
	payload = append(payload, 0x02, 0x00)             // status
	payload = append(payload, 0xFF, 0x81)             // capability upper
	payload = append(payload, 21)                     // auth data len
	payload = append(payload, make([]byte, 10)...)    // reserved
	payload = append(payload, []byte("plugin_data2!!!!!")...)
	payload = append(payload, 0)
	payload = append(payload, []byte("mysql_native_password")...)
	payload = append(payload, 0)
	return mysqlPacket(0, payload)
}

func mysqlAccessDenied() []byte {
	msg := []byte("Access denied for user (using password: YES) — ATDE canary")
	payload := []byte{0xFF, 0x15, 0x04} // ERR, code 1045
	payload = append(payload, '#')
	payload = append(payload, []byte("28000")...)
	payload = append(payload, msg...)
	return mysqlPacket(2, payload)
}

func mysqlPacket(seq byte, payload []byte) []byte {
	n := len(payload)
	hdr := []byte{byte(n), byte(n >> 8), byte(n >> 16), seq}
	return append(hdr, payload...)
}

func (s *Server) serveFTP(done <-chan struct{}) {
	ln, err := net.Listen("tcp", s.cfg.FTPAddr)
	if err != nil {
		s.log.Warn("ftp bait failed", "err", err)
		return
	}
	go func() {
		<-done
		_ = ln.Close()
	}()
	s.log.Info("honeypot ftp bait listening", "addr", s.cfg.FTPAddr)
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-done:
				return
			default:
				continue
			}
		}
		go s.handleFTP(c)
	}
}

func (s *Server) handleFTP(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(45 * time.Second))
	ip := catch.StripPort(c.RemoteAddr().String())
	br := bufio.NewReader(c)
	_, _ = fmt.Fprintf(c, "220 ATDE FTP canary ready.\r\n")
	user, pass := "", ""
loop:
	for i := 0; i < 12; i++ {
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "USER "):
			user = strings.TrimSpace(line[5:])
			_, _ = fmt.Fprintf(c, "331 Password required for %s.\r\n", user)
		case strings.HasPrefix(upper, "PASS "):
			pass = strings.TrimSpace(line[5:])
			_, _ = fmt.Fprintf(c, "530 Login incorrect.\r\n")
			break loop
		case strings.HasPrefix(upper, "QUIT"):
			_, _ = fmt.Fprintf(c, "221 Goodbye.\r\n")
			break loop
		case strings.HasPrefix(upper, "SYST"):
			_, _ = fmt.Fprintf(c, "215 UNIX Type: L8\r\n")
		case strings.HasPrefix(upper, "FEAT") || strings.HasPrefix(upper, "HELP"):
			_, _ = fmt.Fprintf(c, "211-Features:\r\n211 End\r\n")
		default:
			_, _ = fmt.Fprintf(c, "500 Unknown command.\r\n")
		}
	}
	fp := fingerprint.FromService("ftp-bait", user, pass)
	raw, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	s.recordServiceHit(ip, "ftp-bait", "/ftp", string(raw), fp)
}

func (s *Server) serveSMTP(done <-chan struct{}) {
	ln, err := net.Listen("tcp", s.cfg.SMTPAddr)
	if err != nil {
		s.log.Warn("smtp bait failed", "err", err)
		return
	}
	go func() {
		<-done
		_ = ln.Close()
	}()
	s.log.Info("honeypot smtp bait listening", "addr", s.cfg.SMTPAddr)
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-done:
				return
			default:
				continue
			}
		}
		go s.handleSMTP(c)
	}
}

func (s *Server) handleSMTP(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(45 * time.Second))
	ip := catch.StripPort(c.RemoteAddr().String())
	br := bufio.NewReader(c)
	_, _ = fmt.Fprintf(c, "220 %s ESMTP ATDE canary\r\n", s.site.HostHint)
	user, pass := "", ""
loop:
	for i := 0; i < 16; i++ {
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO") || strings.HasPrefix(upper, "HELO"):
			_, _ = fmt.Fprintf(c, "250-%s Hello\r\n250-AUTH LOGIN PLAIN\r\n250 SIZE 10240000\r\n", s.site.HostHint)
		case strings.HasPrefix(upper, "AUTH LOGIN"):
			_, _ = fmt.Fprintf(c, "334 VXNlcm5hbWU6\r\n") // "Username:"
			uLine, _ := br.ReadString('\n')
			user = strings.TrimSpace(uLine)
			_, _ = fmt.Fprintf(c, "334 UGFzc3dvcmQ6\r\n") // "Password:"
			pLine, _ := br.ReadString('\n')
			pass = strings.TrimSpace(pLine)
			_, _ = fmt.Fprintf(c, "535 5.7.8 Authentication failed\r\n")
			break loop
		case strings.HasPrefix(upper, "AUTH PLAIN"):
			pass = strings.TrimSpace(line)
			_, _ = fmt.Fprintf(c, "535 5.7.8 Authentication failed\r\n")
			break loop
		case strings.HasPrefix(upper, "MAIL FROM") || strings.HasPrefix(upper, "RCPT TO"):
			_, _ = fmt.Fprintf(c, "550 Relay not permitted\r\n")
		case strings.HasPrefix(upper, "QUIT"):
			_, _ = fmt.Fprintf(c, "221 Bye\r\n")
			break loop
		default:
			_, _ = fmt.Fprintf(c, "502 Command not implemented\r\n")
		}
	}
	fp := fingerprint.FromService("smtp-bait", user, pass)
	raw, _ := json.Marshal(map[string]string{"username": user, "secret": pass})
	s.recordServiceHit(ip, "smtp-bait", "/smtp", string(raw), fp)
}

func (s *Server) serveElastic(done <-chan struct{}) {
	ln, err := net.Listen("tcp", s.cfg.ESAddr)
	if err != nil {
		s.log.Warn("elasticsearch bait failed", "err", err)
		return
	}
	go func() {
		<-done
		_ = ln.Close()
	}()
	s.log.Info("honeypot elasticsearch bait listening", "addr", s.cfg.ESAddr)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ip := catch.StripPort(r.RemoteAddr)
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			ip = strings.TrimSpace(strings.Split(xff, ",")[0])
		}
		fp := fingerprint.FromService("elastic-bait", "", r.URL.Path+" "+r.UserAgent())
		s.recordServiceHit(ip, "elastic-bait", r.URL.Path, r.UserAgent(), fp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"atde-canary","cluster_name":"atde-decoy","cluster_uuid":"ATDE-CANARY","version":{"number":"8.11.0"},"tagline":"You Know, for Search — ATDE honeypot"}`))
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-done
		_ = srv.Close()
	}()
	_ = srv.Serve(ln)
}

func (s *Server) serveMongo(done <-chan struct{}) {
	ln, err := net.Listen("tcp", s.cfg.MongoAddr)
	if err != nil {
		s.log.Warn("mongo bait failed", "err", err)
		return
	}
	go func() {
		<-done
		_ = ln.Close()
	}()
	s.log.Info("honeypot mongo bait listening", "addr", s.cfg.MongoAddr)
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-done:
				return
			default:
				continue
			}
		}
		go s.handleMongo(c)
	}
}

func (s *Server) handleMongo(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	ip := catch.StripPort(c.RemoteAddr().String())
	buf := make([]byte, 512)
	n, _ := c.Read(buf)
	payload := base64.StdEncoding.EncodeToString(buf[:n])
	// Minimal isMaster-ish BSON reply is complex; close after logging — scanners still hit.
	fp := fingerprint.FromService("mongo-bait", "", payload)
	s.recordServiceHit(ip, "mongo-bait", "/mongo", payload, fp)
}

func (s *Server) recordServiceHit(ip, service, path, payload string, fp fingerprint.Result) {
	now := time.Now().UTC()
	evt := models.RawHoneypotEvent{
		ID: "evt_raw_hp_" + now.Format("20060102150405.000000"), Timestamp: now, Source: "honeypot",
		Data: models.HoneypotData{
			Service: service, RemoteAddr: ip, Method: "TCP", Path: path,
			BodyB64: base64.StdEncoding.EncodeToString([]byte(payload)),
		},
	}
	if s.metrics != nil {
		s.metrics.HoneypotHits.Add(1)
		if strings.Contains(service, "auth") || strings.Contains(service, "telnet") || strings.Contains(service, "ssh") || strings.Contains(service, "ftp") || strings.Contains(service, "mysql") {
			s.metrics.AuthBurns.Add(1)
		}
	}
	actions := []string{"recorded"}
	rec := catch.Record{
		ID: "catch_" + evt.ID, CaughtAt: now, Source: "honeypot",
		IP: ip, Service: service, Path: path, Method: "TCP",
		Reason: "honeypot_hit", Actions: actions,
		Tags: fp.Tags, Tool: fp.Tool, Severity: fp.Severity, Summary: fp.Summary,
		Techniques: fp.Techniques,
		Meta:       map[string]string{},
	}
	if len(payload) > 0 {
		snip := payload
		if len(snip) > 512 {
			snip = snip[:512] + "…"
		}
		rec.Meta["body_snippet"] = snip
	}
	if s.ledger != nil {
		_ = s.ledger.Record(rec)
		if s.metrics != nil {
			s.metrics.CatchRecords.Add(1)
		}
	}
	if s.bus != nil {
		raw, _ := json.Marshal(evt)
		_, _ = s.bus.Publish(models.SubjectRawHoneypot, raw)
	}
	s.maybeBlock(ip, fp.Severity, service)
	s.log.Info("honeypot hit", "service", service, "remote", ip, "sev", fp.Severity, "id", evt.ID)
}
