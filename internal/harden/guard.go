package harden

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"time"

	"github.com/theworker02/ATDE/v2/internal/config"
	"github.com/theworker02/ATDE/v2/internal/models"
	"github.com/theworker02/ATDE/v2/internal/natsbus"
)

// AlertFunc publishes a compromise signal before wipe (optional).
type AlertFunc func(evt models.CompromisedEvent)

// Guard is the runtime integrity / anti-analysis controller.
type Guard struct {
	cfg      config.HardenConfig
	sc       *SecureContext
	log      *slog.Logger
	bus      *natsbus.Bus
	buildSig string
	mode     string // soft | hard
}

// BuildSignature is injected via -ldflags "-X github.com/.../internal/harden.BuildSignature=..."
var BuildSignature string

// ExpectedBinaryHash is injected at build time for disk integrity checks.
var ExpectedBinaryHash string

func NewGuard(cfg config.HardenConfig, sc *SecureContext, bus *natsbus.Bus, log *slog.Logger) *Guard {
	mode := "soft"
	if cfg.HardMode {
		mode = "hard"
	}
	return &Guard{cfg: cfg, sc: sc, bus: bus, log: log, buildSig: BuildSignature, mode: mode}
}

// Start runs initial checks, kernel hardeners, and a background watcher.
func (g *Guard) Start(ctx context.Context) error {
	if !g.cfg.Enabled {
		g.log.Info("node hardening disabled")
		return nil
	}
	g.log.Info("node hardening engaged", "mode", g.mode, "os", runtime.GOOS, "build", g.buildSig)

	g.sc.LockSensitivePages(g.log)

	if g.cfg.DisableDumpable {
		if err := disableDumpable(); err != nil {
			g.log.Warn("PR_SET_DUMPABLE failed", "err", err)
		} else {
			g.log.Info("memory dumpability disabled")
		}
	}
	if g.cfg.Seccomp {
		if err := ApplySeccompSandbox(g.log); err != nil {
			g.log.Warn("seccomp sandbox", "err", err)
		}
	}

	g.runChecks("startup")

	if g.cfg.WatchInterval > 0 {
		go g.watch(ctx)
	}
	return nil
}

func (g *Guard) watch(ctx context.Context) {
	t := time.NewTicker(g.cfg.WatchInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.runChecks("watch")
		}
	}
}

func (g *Guard) runChecks(phase string) {
	if g.cfg.AntiDebug {
		if reason, hit := checkTracerPID(); hit {
			g.trip(reason)
			return
		}
		if reason, hit := checkPtrace(); hit {
			g.trip(reason)
			return
		}
	}
	if g.cfg.TimingCheck {
		if reason, hit := checkTimingAnomaly(g.cfg.TimingThreshold); hit {
			g.trip(reason)
			return
		}
	}
	if g.cfg.IntegrityCheck && ExpectedBinaryHash != "" {
		if reason, hit := verifySelfBinaryIntegrity(ExpectedBinaryHash); hit {
			g.trip(reason)
			return
		}
	}
	g.log.Debug("integrity checks ok", "phase", phase)
}

func (g *Guard) trip(reason string) {
	g.log.Error("CRITICAL SECURITY VIOLATION", "reason", reason, "mode", g.mode)
	host, _ := os.Hostname()
	evt := models.CompromisedEvent{
		ID:        "evt_cmp_" + time.Now().UTC().Format("20060102150405.000000"),
		Timestamp: time.Now().UTC(),
		Hostname:  host,
		PID:       os.Getpid(),
		Reason:    reason,
		BuildSig:  g.buildSig,
		Mode:      g.mode,
	}
	g.alertMesh(evt)

	if g.mode == "soft" {
		g.log.Warn("soft mode: secrets zeroized but process continues (dev/safe)")
		g.sc.ZeroizeMemory()
		return
	}

	g.sc.ZeroizeMemory()
	// Hard mode: immediate kill — avoid deferred cleanup interceptors.
	killSelf()
}

func (g *Guard) alertMesh(evt models.CompromisedEvent) {
	if g.bus == nil {
		return
	}
	raw, err := json.Marshal(evt)
	if err != nil {
		return
	}
	// Best-effort; must not block wipe path long.
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := g.bus.Publish(models.SubjectCompromised, raw); err != nil {
			g.log.Error("compromise alert publish failed", "err", err)
		} else {
			g.log.Info("compromise alert published", "id", evt.ID)
		}
	}()
	select {
	case <-done:
	case <-ctx.Done():
		g.log.Warn("compromise alert timed out")
	}
}

// Status returns a short description for logging.
func (g *Guard) Status() string {
	return fmt.Sprintf("enabled=%v mode=%s anti_debug=%v seccomp=%v",
		g.cfg.Enabled, g.mode, g.cfg.AntiDebug, g.cfg.Seccomp)
}
