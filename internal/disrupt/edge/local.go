package edge

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	ipsetName      = "atde_honeypot_bans"
	ipsetTimeoutSec = 86400 // 24h auto-expire
)

// LocalFirewall applies OS-level IP blocks with no cloud dependency.
// Linux prefers ipset (O(1) lookups); falls back to nft/iptables.
// Windows uses netsh advfirewall. All exec uses argv slices (no shell).
type LocalFirewall struct {
	Log     *slog.Logger
	Enabled bool
	DryRun  bool

	mu      sync.Mutex
	ready   bool // ipset + iptables hook prepared
	useSet  bool
}

func NewLocalFirewall(enabled, dryRun bool, log *slog.Logger) *LocalFirewall {
	return &LocalFirewall{Log: log, Enabled: enabled, DryRun: dryRun}
}

// EnsureReady creates the ipset and one-time iptables match rule on Linux.
func (lf *LocalFirewall) EnsureReady(ctx context.Context) error {
	if lf == nil || !lf.Enabled || lf.DryRun {
		return nil
	}
	lf.mu.Lock()
	defer lf.mu.Unlock()
	if lf.ready {
		return nil
	}
	if runtime.GOOS != "linux" {
		lf.ready = true
		return nil
	}
	if err := lf.setupIPSet(ctx); err != nil {
		if lf.Log != nil {
			lf.Log.Warn("ipset setup failed; will use per-IP iptables/nft", "err", err)
		}
		lf.useSet = false
	} else {
		lf.useSet = true
	}
	lf.ready = true
	return nil
}

func (lf *LocalFirewall) setupIPSet(ctx context.Context) error {
	if _, err := exec.LookPath("ipset"); err != nil {
		return fmt.Errorf("ipset not in PATH: %w", err)
	}
	// Create hash:ip set (ignore "already exists")
	out, err := run(ctx, "ipset", "create", ipsetName, "hash:ip", "timeout", fmt.Sprintf("%d", ipsetTimeoutSec), "-exist")
	if err != nil {
		return fmt.Errorf("ipset create: %w (%s)", err, truncate(string(out), 120))
	}
	// Bind once: DROP sources in the set
	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("iptables not in PATH: %w", err)
	}
	// Check if rule already present to avoid duplicates
	check := exec.CommandContext(ctx, "iptables", "-C", "INPUT", "-m", "set", "--match-set", ipsetName, "src", "-j", "DROP")
	if check.Run() != nil {
		out, err = run(ctx, "iptables", "-I", "INPUT", "-m", "set", "--match-set", ipsetName, "src", "-j", "DROP")
		if err != nil {
			return fmt.Errorf("iptables match-set: %w (%s)", err, truncate(string(out), 120))
		}
	}
	if lf.Log != nil {
		lf.Log.Info("local firewall ipset ready", "set", ipsetName, "timeout_sec", ipsetTimeoutSec)
	}
	return nil
}

// BlockIP is the mandatory local containment path.
func (lf *LocalFirewall) BlockIP(ctx context.Context, ip, reason string) error {
	if lf == nil || !lf.Enabled {
		return fmt.Errorf("local firewall disabled")
	}
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid ip")
	}
	if isPrivateOrLocal(ip) {
		return fmt.Errorf("refusing private/local ip")
	}
	if lf.DryRun {
		if lf.Log != nil {
			lf.Log.Info("local firewall dry-run", "ip", ip, "reason", reason)
		}
		return nil
	}
	_ = lf.EnsureReady(ctx)

	lf.mu.Lock()
	useSet := lf.useSet
	lf.mu.Unlock()

	var err error
	switch runtime.GOOS {
	case "linux":
		if useSet {
			err = lf.blockViaIPSet(ctx, ip)
		} else {
			err = lf.blockViaLegacyLinux(ctx, ip, reason)
		}
	case "windows":
		err = lf.blockViaNetsh(ctx, ip)
	default:
		err = fmt.Errorf("local firewall unsupported on %s", runtime.GOOS)
	}
	if err != nil {
		return err
	}
	if lf.Log != nil {
		lf.Log.Info("local firewall rule applied", "ip", ip, "backend", lf.backendName(useSet), "reason", truncate(reason, 80))
	}
	return nil
}

func (lf *LocalFirewall) backendName(useSet bool) string {
	switch runtime.GOOS {
	case "linux":
		if useSet {
			return "ipset"
		}
		return "iptables/nft"
	case "windows":
		return "netsh"
	default:
		return runtime.GOOS
	}
}

func (lf *LocalFirewall) blockViaIPSet(ctx context.Context, ip string) error {
	out, err := run(ctx, "ipset", "add", ipsetName, ip, "timeout", fmt.Sprintf("%d", ipsetTimeoutSec), "-exist")
	if err != nil {
		return fmt.Errorf("ipset add: %w (%s)", err, truncate(string(out), 160))
	}
	return nil
}

func (lf *LocalFirewall) blockViaLegacyLinux(ctx context.Context, ip, reason string) error {
	comment := "atde-" + sanitizeArg(truncate(reason, 40))
	if _, err := exec.LookPath("nft"); err == nil {
		out, err := run(ctx, "nft", "add", "rule", "inet", "filter", "input", "ip", "saddr", ip, "drop", "comment", comment)
		if err == nil {
			return nil
		}
		if lf.Log != nil {
			lf.Log.Debug("nft failed, trying iptables", "err", err, "out", truncate(string(out), 80))
		}
	}
	out, err := run(ctx, "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", "atde")
	if err != nil {
		return fmt.Errorf("iptables: %w (%s)", err, truncate(string(out), 160))
	}
	return nil
}

func (lf *LocalFirewall) blockViaNetsh(ctx context.Context, ip string) error {
	// argv only — never shell. Rule name is sanitized.
	name := "ATDE-Block-" + sanitizeArg(ip)
	out, err := run(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
		"name="+name, "dir=in", "action=block", "remoteip="+ip)
	if err != nil {
		// Duplicate rule is acceptable on re-hit
		if strings.Contains(strings.ToLower(string(out)), "already exists") {
			return nil
		}
		return fmt.Errorf("netsh: %w (%s)", err, truncate(string(out), 160))
	}
	return nil
}

// run executes a binary with explicit argv (no /bin/sh).
func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

func sanitizeArg(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_', r == ':':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		return "atde"
	}
	return out
}
