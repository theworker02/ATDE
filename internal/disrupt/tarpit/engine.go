package tarpit

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/theworker02/blind-botnet/v2/internal/config"
)

// Engine holds inbound scanner connections open with ultra-slow responses.
// Operates only on listeners you own (honeypot / decoy ports).
type Engine struct {
	cfg     config.TarpitConfig
	log     *slog.Logger
	active  atomic.Int64
	engaged atomic.Uint64
}

func New(cfg config.TarpitConfig, log *slog.Logger) *Engine {
	return &Engine{cfg: cfg, log: log}
}

func (e *Engine) Active() int64 { return e.active.Load() }
func (e *Engine) Engaged() uint64 { return e.engaged.Load() }

// HTTPHandler streams chunked responses at 1 byte per Interval.
func (e *Engine) HTTPHandler(w http.ResponseWriter, r *http.Request) {
	if !e.cfg.Enabled {
		http.Error(w, "tarpit disabled", http.StatusServiceUnavailable)
		return
	}
	if max := e.cfg.MaxConns; max > 0 && e.active.Load() >= int64(max) {
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	e.active.Add(1)
	e.engaged.Add(1)
	defer e.active.Add(-1)

	e.log.Info("tarpit engaged",
		"proto", "http",
		"remote", r.RemoteAddr,
		"ua", r.UserAgent(),
		"path", r.URL.Path,
		"active", e.active.Load(),
	)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-ATDE-Tarpit", "1")
	w.WriteHeader(http.StatusOK)

	interval := e.cfg.ByteInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	maxDur := e.cfg.MaxDuration
	deadline := time.Time{}
	if maxDur > 0 {
		deadline = time.Now().Add(maxDur)
	}

	buf := make([]byte, 1)
	for {
		if !deadline.IsZero() && time.Now().After(deadline) {
			e.log.Info("tarpit released", "reason", "max_duration", "remote", r.RemoteAddr)
			return
		}
		if _, err := rand.Read(buf); err != nil {
			return
		}
		if _, err := fmt.Fprintf(w, "%x", buf[0]); err != nil {
			e.log.Info("tarpit released", "reason", "client_disconnect", "remote", r.RemoteAddr)
			return
		}
		flusher.Flush()
		time.Sleep(interval)
	}
}

// ServeTCP accepts raw TCP connections and drips bytes slowly (SSH/SMTP-style decoy).
func (e *Engine) ServeTCP(ctx context.Context, addr, banner string) error {
	if !e.cfg.Enabled {
		e.log.Info("tcp tarpit disabled", "addr", addr)
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	e.log.Info("tcp tarpit listening", "addr", addr)
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	interval := e.cfg.ByteInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				continue
			}
		}
		if max := e.cfg.MaxConns; max > 0 && e.active.Load() >= int64(max) {
			_ = conn.Close()
			continue
		}
		go e.handleTCP(conn, banner, interval)
	}
}

func (e *Engine) handleTCP(conn net.Conn, banner string, interval time.Duration) {
	e.active.Add(1)
	e.engaged.Add(1)
	defer e.active.Add(-1)
	defer conn.Close()

	remote := conn.RemoteAddr().String()
	e.log.Info("tarpit engaged", "proto", "tcp", "remote", remote, "active", e.active.Load())

	_ = conn.SetDeadline(time.Time{}) // no deadline — intentional stall
	if banner != "" {
		_, _ = conn.Write([]byte(banner))
	}

	maxDur := e.cfg.MaxDuration
	deadline := time.Time{}
	if maxDur > 0 {
		deadline = time.Now().Add(maxDur)
	}

	buf := make([]byte, 1)
	for {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return
		}
		if _, err := rand.Read(buf); err != nil {
			return
		}
		if _, err := conn.Write([]byte(fmt.Sprintf("%x", buf[0]))); err != nil {
			e.log.Info("tarpit released", "reason", "client_disconnect", "remote", remote)
			return
		}
		time.Sleep(interval)
	}
}
