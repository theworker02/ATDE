package honeypot

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/theworker02/blind-botnet/internal/catch"
	"github.com/theworker02/blind-botnet/internal/fingerprint"
	"github.com/theworker02/blind-botnet/internal/models"
)

func (s *Server) serveSSH(done <-chan struct{}) {
	ln, err := net.Listen("tcp", s.cfg.SSHAddr)
	if err != nil {
		s.log.Warn("ssh honeypot failed", "err", err)
		return
	}
	go func() {
		<-done
		_ = ln.Close()
	}()
	s.log.Info("honeypot ssh listening", "addr", s.cfg.SSHAddr, "mode", "password-burn")
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-done:
				return
			default:
				continue
			}
		}
		go s.handleSSHConn(conn)
	}
}

// StartSSH exposes the SSH password-burn listener for tests and custom supervisors.
func (s *Server) StartSSH(done <-chan struct{}) {
	s.serveSSH(done)
}

func (s *Server) handleSSHConn(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(45 * time.Second))
	banner := "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n"
	_, _ = c.Write([]byte(banner))

	br := bufio.NewReader(c)
	clientBanner, _ := br.ReadString('\n')
	ip := catch.StripPort(c.RemoteAddr().String())

	_, _ = fmt.Fprintf(c, "\r\nAtlas gateway — authorized use only\r\n")
	time.Sleep(300 * time.Millisecond)
	_, _ = fmt.Fprintf(c, "login as: ")
	userLine, _ := br.ReadString('\n')
	user := strings.TrimSpace(userLine)
	if user == "" {
		user = "unknown"
	}
	time.Sleep(200 * time.Millisecond)
	_, _ = fmt.Fprintf(c, "%s@%s's password: ", user, s.site.HostHint)
	passLine, _ := br.ReadString('\n')
	pass := strings.TrimSpace(passLine)

	transcript := map[string]string{
		"client_banner": strings.TrimSpace(clientBanner),
		"server_banner": strings.TrimSpace(banner),
		"username":      user,
		"password":      pass,
		"result":        "permission_denied",
	}
	rawJSON, _ := json.Marshal(transcript)
	fp := fingerprint.FromService("ssh-auth-burn", user, pass)

	now := time.Now().UTC()
	evt := models.RawHoneypotEvent{
		ID: "evt_raw_hp_" + now.Format("20060102150405.000000"), Timestamp: now, Source: "honeypot",
		Data: models.HoneypotData{
			Service: "ssh-auth-burn", RemoteAddr: ip,
			BodyB64: base64.StdEncoding.EncodeToString(rawJSON),
			Method:  "SSH",
			Path:    "/ssh",
		},
	}
	if s.metrics != nil {
		s.metrics.HoneypotHits.Add(1)
		s.metrics.AuthBurns.Add(1)
	}
	if s.ledger != nil {
		_ = s.ledger.Record(catch.Record{
			ID: "catch_" + evt.ID, CaughtAt: now, Source: "honeypot",
			IP: ip, Service: "ssh-auth-burn", Path: "/ssh", Reason: "ssh_password_burn",
			Actions: []string{"recorded", "auth_burn"},
			Meta:    map[string]string{"username": user, "body_snippet": string(rawJSON)},
			Tags: fp.Tags, Tool: fp.Tool, Severity: fp.Severity, Summary: fp.Summary,
		})
		if s.metrics != nil {
			s.metrics.CatchRecords.Add(1)
		}
	}
	if s.bus != nil {
		raw, _ := json.Marshal(evt)
		_, _ = s.bus.Publish(models.SubjectRawHoneypot, raw)
	}
	s.maybeBlock(ip, fp.Severity, "ssh-auth-burn")

	time.Sleep(800 * time.Millisecond)
	_, _ = fmt.Fprintf(c, "\r\nPermission denied, please try again.\r\n")
	time.Sleep(400 * time.Millisecond)
	_, _ = fmt.Fprintf(c, "%s@%s's password: ", user, s.site.HostHint)
	_, _ = br.ReadString('\n')
	time.Sleep(600 * time.Millisecond)
	_, _ = fmt.Fprintf(c, "\r\nPermission denied (publickey,password).\r\nConnection closed.\r\n")
	s.log.Info("honeypot hit", "service", "ssh-auth-burn", "remote", ip, "user", user, "id", evt.ID)
}
