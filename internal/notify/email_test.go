package notify

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/gopenpgp/v3/crypto"

	"github.com/theworker02/ATDE/v2/internal/catch"
)

func TestEncryptPGPRoundTrip(t *testing.T) {
	pgp := crypto.PGP()
	genHandle := pgp.KeyGeneration().
		AddUserId("ATDE Test", "atde-test@example.com").
		New()
	priv, err := genHandle.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := priv.ToPublic()
	if err != nil {
		t.Fatal(err)
	}
	armoredPub, err := pub.Armor()
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.NewKeyFromArmored(armoredPub)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := encryptPGP(key, "secret attack report")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ct, "BEGIN PGP MESSAGE") {
		t.Fatalf("expected armored message, got %q", ct[:min(40, len(ct))])
	}
	dec, err := pgp.Decryption().DecryptionKey(priv).New()
	if err != nil {
		t.Fatal(err)
	}
	out, err := dec.Decrypt([]byte(ct), crypto.Armor)
	if err != nil {
		t.Fatal(err)
	}
	if string(out.Bytes()) != "secret attack report" {
		t.Fatalf("got %q", out.Bytes())
	}
}

func TestEmailSendSMTPNone(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var got string
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(c)
		_, _ = io.WriteString(c, "220 test ESMTP\r\n")
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
				_, _ = io.WriteString(c, "250-localhost\r\n250 OK\r\n")
			case strings.HasPrefix(line, "MAIL"), strings.HasPrefix(line, "RCPT"):
				_, _ = io.WriteString(c, "250 OK\r\n")
			case strings.HasPrefix(line, "DATA"):
				_, _ = io.WriteString(c, "354 End data\r\n")
				var data strings.Builder
				for {
					l, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if l == ".\r\n" {
						break
					}
					data.WriteString(l)
				}
				got = data.String()
				_, _ = io.WriteString(c, "250 OK\r\n")
			case strings.HasPrefix(line, "QUIT"):
				_, _ = io.WriteString(c, "221 bye\r\n")
				return
			default:
				_, _ = io.WriteString(c, "250 OK\r\n")
			}
		}
	}()

	host, port, _ := net.SplitHostPort(ln.Addr().String())
	e, err := NewEmail(EmailConfig{
		To: "owner@example.com", From: "atde@example.com",
		Host: host, Port: port, TLSMode: "none",
		MinSeverity: 1, Cooldown: time.Millisecond,
		NodeName: "test-node",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	err = e.SendAttackAlert(catch.Record{
		IP: "203.0.113.9", Source: "honeypot", Service: "http-login",
		Path: "/login", Severity: 55, Summary: "credential attempt",
		Actions: []string{"recorded"}, CaughtAt: time.Now().UTC(),
		Tags: []string{"cred-spray"}, Reason: "honeypot_hit",
	})
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if !strings.Contains(got, "HAS BEEN RECORDED") || !strings.Contains(got, "203.0.113.9") {
		t.Fatalf("mail body missing content: %q", got)
	}
}

func TestFormatAttackPlain(t *testing.T) {
	s := formatAttackPlain(catch.Record{
		IP: "1.2.3.4", Source: "honeypot", Service: "ssh-auth-burn",
		Severity: 65, Summary: "SSH auth", Actions: []string{"recorded"},
		CaughtAt: time.Now().UTC(),
	}, "node-a", "http://x/console")
	if !strings.Contains(s, "HAS BEEN RECORDED") || !strings.Contains(s, "1.2.3.4") {
		t.Fatal(s)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
