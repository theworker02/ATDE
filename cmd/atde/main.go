package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/theworker02/blind-botnet/internal/catch"
	"github.com/theworker02/blind-botnet/internal/config"
	"github.com/theworker02/blind-botnet/internal/deception"
	"github.com/theworker02/blind-botnet/internal/disrupt/active"
	"github.com/theworker02/blind-botnet/internal/disrupt/dispatcher"
	"github.com/theworker02/blind-botnet/internal/disrupt/edge"
	"github.com/theworker02/blind-botnet/internal/disrupt/tarpit"
	"github.com/theworker02/blind-botnet/internal/doctor"
	"github.com/theworker02/blind-botnet/internal/enrich"
	"github.com/theworker02/blind-botnet/internal/extract"
	"github.com/theworker02/blind-botnet/internal/fleet"
	"github.com/theworker02/blind-botnet/internal/harden"
	"github.com/theworker02/blind-botnet/internal/ingest/ct"
	"github.com/theworker02/blind-botnet/internal/ingest/honeypot"
	"github.com/theworker02/blind-botnet/internal/natsbus"
	"github.com/theworker02/blind-botnet/internal/notify"
	"github.com/theworker02/blind-botnet/internal/ops"
	"github.com/theworker02/blind-botnet/internal/policy"
	"github.com/theworker02/blind-botnet/internal/publish"
	"github.com/theworker02/blind-botnet/internal/sinkhole"
	"github.com/theworker02/blind-botnet/internal/trace/infra"
)

// Set via -ldflags "-X main.version=..."
var version = "2.0.0"

func main() {
	cfgPath := flag.String("config", "configs/config.yaml", "config path")
	mode := flag.String("mode", "all", "all|catch-node|ct|honeypot|extract|enrich|dispatch|active|tarpit|sinkhole|publish|deception|caught|catch|dossier|export|abuse|stix|seed-demo|watch|doctor|status|version")
	limit := flag.Int("limit", 50, "max catch records / dossiers to show")
	ipFilter := flag.String("ip", "", "filter by IP (caught|dossier|export|abuse|stix)")
	outPath := flag.String("out", "", "write export to file (mode=export|abuse|stix)")
	seedPath := flag.String("seed", "docs/data-room/demo-evidence/events.jsonl", "JSONL path for mode=seed-demo")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion || *mode == "version" {
		fmt.Println(version)
		return
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		// doctor / caught can still run with partial help if config missing
		if *mode != "doctor" && *mode != "caught" && *mode != "catch" && *mode != "dossier" && *mode != "export" && *mode != "abuse" && *mode != "stix" && *mode != "seed-demo" && *mode != "watch" {
			fmt.Fprintf(os.Stderr, "config: %v\n", err)
			os.Exit(1)
		}
		cfg = &config.Config{}
		cfg.App.OpsAddr = ":9091"
		cfg.Ingest.Honeypot.HTTPAddr = ":8080"
		cfg.Ingest.Honeypot.SSHAddr = ":2222"
		cfg.Deception.ListenAddr = ":8443"
		cfg.NATS.URL = os.Getenv("NATS_URL")
		if cfg.NATS.URL == "" {
			cfg.NATS.URL = "nats://127.0.0.1:4222"
		}
		fmt.Fprintf(os.Stderr, "warning: config load failed (%v); using defaults for offline modes\n", err)
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parseLevel(cfg.App.LogLevel)}))

	switch *mode {
	case "caught", "catch":
		printCaught(*limit, *ipFilter)
		return
	case "dossier":
		printDossier(*ipFilter, *limit)
		return
	case "export":
		exportCaught(*ipFilter, *outPath)
		return
	case "abuse":
		exportAbuse(*ipFilter, *outPath)
		return
	case "stix":
		exportSTIX(*ipFilter, *outPath)
		return
	case "seed-demo":
		seedDemo(*seedPath)
		return
	case "watch":
		watchCaught()
		return
	case "doctor":
		runDoctor(cfg)
		return
	case "status":
		printStatus(cfg)
		return
	}

	log.Info("ATDE starting",
		"version", version,
		"mode", *mode,
		"live", cfg.App.Live,
		"dry_run", cfg.App.DryRun,
		"local_firewall", cfg.ActiveDefense.Edge.LocalFirewall,
		"active_defense", cfg.ActiveDefense.Enabled,
		"sinkhole", cfg.Sinkhole.Enabled,
		"publish", cfg.Publish.Enabled,
		"deception", cfg.Deception.Enabled,
		"nats", cfg.NATS.URL,
	)
	if cfg.App.Live {
		log.Warn("LIVE MODE: local-first containment on; cloud bans best-effort when credentials are set; dossiers under data/caught/")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	catchNode := *mode == "catch-node"
	var bus *natsbus.Bus
	if catchNode || os.Getenv("ATDE_NATS_OPTIONAL") == "1" {
		b, err := natsbus.Connect(cfg.NATS.URL, log)
		if err != nil {
			log.Warn("NATS unavailable — recording attacks to disk only (no pipeline)", "err", err)
		} else {
			bus = b
		}
	} else {
		b, err := natsbus.Connect(cfg.NATS.URL, log)
		if err != nil {
			log.Error("nats", "err", err)
			os.Exit(1)
		}
		bus = b
	}
	defer bus.Close()

	sec := harden.NewSecureContext()
	if v := os.Getenv("ATDE_MASTER_KEY"); v != "" {
		sec.SetSecret("master", []byte(v))
	}
	if v := os.Getenv("NATS_AUTH_TOKEN"); v != "" {
		sec.SetSecret("nats", []byte(v))
	}
	guard := harden.NewGuard(cfg.Harden, sec, bus, log)
	if err := guard.Start(ctx); err != nil {
		log.Error("harden", "err", err)
		os.Exit(1)
	}
	defer sec.ZeroizeMemory()

	ledger := catch.New("./data/caught")
	var hooks []catch.OnRecord
	if whURL := strings.TrimSpace(os.Getenv("ATDE_WEBHOOK_URL")); whURL != "" {
		wh := notify.NewWebhook(whURL, os.Getenv("ATDE_WEBHOOK_TOKEN"), log)
		hooks = append(hooks, wh.Handle)
		log.Info("webhook notifier enabled")
	}
	mail, err := notify.EmailFromEnv(log)
	if err != nil {
		log.Error("email notifier config", "err", err)
		os.Exit(1)
	}
	if mail != nil {
		hooks = append(hooks, mail.Handle)
		log.Info("encrypted email alerts enabled",
			"to", os.Getenv("ATDE_ALERT_TO")+os.Getenv("ATDE_ALERT_EMAIL")+os.Getenv("ATDE_OWNER_EMAIL"),
			"pgp", os.Getenv("ATDE_PGP_PUBLIC_KEY_FILE") != "" || os.Getenv("ATDE_PGP_PUBLIC_KEY") != "",
		)
		if os.Getenv("ATDE_ALERT_BOOT") != "0" {
			go func() {
				time.Sleep(2 * time.Second)
				if err := mail.SendBootAlert(); err != nil {
					log.Warn("boot alert email failed", "err", err)
				} else {
					log.Info("boot alert email sent to owner")
				}
			}()
		}
	}
	if len(hooks) > 0 {
		ledger = ledger.WithHook(notify.Fanout(hooks...))
	}
	metrics := ops.NewMetrics(version, *mode)
	fleetStore := fleet.NewStore("./data/fleet/bans.json", os.Getenv("ATDE_NODE_NAME"))
	pol := policy.New(policy.DefaultConfig(), log).WithLedger(ledger)
	var edgeBlocker *edge.Blocker
	if cfg.ActiveDefense.Edge.LocalFirewall && (catchNode || cfg.App.Live) {
		edgeBlocker = edge.New(cfg.ActiveDefense.Edge, log)
		pol = pol.WithBlocker(edgeBlocker)
	}
	opsHandler := &ops.Handler{
		Metrics: metrics,
		Ready:   func() bool { return true },
		Catch: &ops.CatchAPI{
			Ledger: ledger,
			Token:  strings.TrimSpace(os.Getenv("ATDE_OPS_TOKEN")),
			Policy: pol,
			Fleet:  fleetStore,
		},
	}

	g, gctx := errgroup.WithContext(ctx)
	start := func(name string, fn func() error) {
		g.Go(func() error {
			log.Info("service start", "name", name)
			if err := fn(); err != nil && err != context.Canceled {
				return fmt.Errorf("%s: %w", name, err)
			}
			return nil
		})
	}

	if cfg.App.OpsAddr != "" && cfg.App.OpsAddr != "off" {
		start("ops-http", func() error {
			log.Info("ops listening", "addr", cfg.App.OpsAddr, "paths", "/console,/v1/campaigns,/v1/fleet/bans,/v1/openapi.json")
			return ops.ListenAndServe(gctx, cfg.App.OpsAddr, opsHandler)
		})
	}

	tp := tarpit.New(cfg.ActiveDefense.Tarpit, log)

	runCT := func() {
		if bus == nil {
			log.Warn("skip ct-streamer: no NATS")
			return
		}
		c := cfg.Ingest.CT
		c.Enabled = true
		start("ct-streamer", func() error { return ct.New(c, cfg.Brands, bus, log).Run(gctx) })
	}
	runHP := func() {
		h := cfg.Ingest.Honeypot
		h.Enabled = true
		if catchNode {
			if h.RedisAddr == "" {
				h.RedisAddr = ":6379"
			}
			if h.TelnetAddr == "" {
				h.TelnetAddr = ":2323"
			}
			if h.BlockAfter == 0 {
				h.BlockAfter = 3
			}
		}
		srv := honeypot.New(h, bus, log).WithLedger(ledger).WithMetrics(metrics).WithPolicy(pol).WithFleet(fleetStore)
		if cfg.ActiveDefense.Tarpit.Enabled {
			srv = srv.WithTarpit(tp)
		}
		if edgeBlocker != nil {
			srv = srv.WithBlocker(edgeBlocker)
		}
		start("honeypot", func() error { return srv.Run(gctx) })
	}
	runExtract := func() {
		if bus == nil {
			log.Warn("skip extract: no NATS")
			return
		}
		start("extract", func() error { return extract.NewWorker(bus, cfg.Brands, log).Run(gctx) })
	}
	runEnrich := func() {
		if bus == nil {
			return
		}
		ig := infra.New(cfg.Trace, log)
		start("enrich", func() error {
			return enrich.New(bus, ig, cfg.Disrupt.MinConfidence, cfg.App.DryRun, log).Run(gctx)
		})
	}
	runDispatch := func() {
		if bus == nil {
			return
		}
		start("dispatch", func() error {
			return dispatcher.New(bus, cfg.Disrupt.EvidenceDir, cfg.App.DryRun, log).Run(gctx)
		})
	}
	runActive := func() {
		if bus == nil {
			log.Warn("skip active-defense pipeline: no NATS (hits still recorded to disk)")
			return
		}
		start("active-defense", func() error {
			return active.New(bus, cfg.ActiveDefense, cfg.Disrupt.EvidenceDir, cfg.App.DryRun, log).Run(gctx)
		})
	}
	runSinkhole := func() {
		if bus == nil {
			return
		}
		sc := cfg.Sinkhole
		sc.Enabled = true
		start("sinkhole", func() error { return sinkhole.New(sc, bus, log).Run(gctx) })
	}
	runPublish := func() {
		if bus == nil {
			return
		}
		pc := cfg.Publish
		pc.Enabled = true
		start("publish", func() error { return publish.New(pc, bus, log).Run(gctx) })
	}
	runDeception := func() {
		dc := cfg.Deception
		dc.Enabled = true
		start("deception", func() error { return deception.New(dc, bus, log).Run(gctx) })
	}

	switch *mode {
	case "catch-node":
		// Public bait box: record every hit. Pipeline extras only if NATS is up.
		log.Info("catch-node mode: deploy publicly, review data/caught/ and :9091/console")
		runHP()
		runDeception()
		if bus != nil {
			runExtract()
			runActive()
		}
	case "all":
		runCT()
		runHP()
		runExtract()
		runEnrich()
		runDispatch()
		runActive()
		runSinkhole()
		runPublish()
		runDeception()
	case "ct":
		runCT()
	case "honeypot", "tarpit":
		runHP()
		runExtract()
		runActive()
	case "extract":
		runExtract()
	case "enrich":
		runEnrich()
	case "dispatch":
		runDispatch()
	case "active":
		runActive()
	case "sinkhole":
		runSinkhole()
	case "publish":
		runPublish()
	case "deception":
		runDeception()
		runActive()
	default:
		log.Error("unknown mode", "mode", *mode)
		fmt.Fprintf(os.Stderr, "modes: all|catch-node|ct|honeypot|extract|enrich|dispatch|active|tarpit|sinkhole|publish|deception|caught|dossier|export|abuse|stix|seed-demo|watch|doctor|status|version\n")
		os.Exit(2)
	}

	if err := g.Wait(); err != nil && err != context.Canceled {
		log.Error("shutdown error", "err", err)
		os.Exit(1)
	}
	log.Info("stopped")
}

func printCaught(limit int, ip string) {
	l := catch.New("./data/caught")
	hits, uniq, err := l.Summary()
	if err != nil {
		fmt.Fprintf(os.Stderr, "catch summary: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("ATDE %s — Caught attackers: %d hits from %d unique IPs (data/caught/)\n\n", version, hits, uniq)
	var recs []catch.Record
	if ip != "" {
		recs, err = l.ListByIP(ip, limit)
	} else {
		recs, err = l.ListRecent(limit)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "list: %v\n", err)
		os.Exit(1)
	}
	if len(recs) == 0 {
		fmt.Println("No catches yet. Expose honeypot ports (8080/2222/8443) to the internet, then:")
		fmt.Println("  curl http://YOUR_PUBLIC_IP:8080/wp-login.php")
		fmt.Println("  go run ./cmd/atde -mode doctor")
		fmt.Println("Console: http://127.0.0.1:9091/console")
		return
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	for _, r := range recs {
		_ = enc.Encode(r)
	}
}

func printDossier(ip string, limit int) {
	l := catch.New("./data/caught")
	if ip == "" {
		list, err := l.ListDossiers(limit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dossiers: %v\n", err)
			os.Exit(1)
		}
		if len(list) == 0 {
			fmt.Println("No dossiers yet.")
			return
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(list)
		return
	}
	d, err := l.GetDossier(ip)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dossier %s: %v\n", ip, err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(d)
}

func exportCaught(ip, out string) {
	if ip == "" {
		fmt.Fprintln(os.Stderr, "export requires -ip")
		os.Exit(2)
	}
	l := catch.New("./data/caught")
	md, err := l.ExportMarkdown(ip)
	if err != nil {
		fmt.Fprintf(os.Stderr, "export: %v\n", err)
		os.Exit(1)
	}
	if out == "" {
		out = filepath.Join("data", "evidence", "atde-"+catch.Sanitize(ip)+".md")
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(out, []byte(md), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(out)
}

func exportAbuse(ip, outDir string) {
	if ip == "" {
		fmt.Fprintln(os.Stderr, "abuse requires -ip")
		os.Exit(2)
	}
	l := catch.New("./data/caught")
	md, stix, err := l.ExportAbuseBundle(ip, outDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "abuse: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(md)
	fmt.Println(stix)
}

func exportSTIX(ip, out string) {
	if ip == "" {
		fmt.Fprintln(os.Stderr, "stix requires -ip")
		os.Exit(2)
	}
	l := catch.New("./data/caught")
	raw, err := l.ExportSTIX(ip)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stix: %v\n", err)
		os.Exit(1)
	}
	if out == "" {
		out = filepath.Join("data", "evidence", "atde-"+catch.Sanitize(ip)+".stix.json")
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(out, []byte(raw), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(out)
}

func seedDemo(path string) {
	l := catch.New("./data/caught")
	n, err := l.SeedFromJSONL(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "seed-demo: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("ATDE %s — seeded %d demo events from %s into data/caught/\n", version, n, path)
	fmt.Println("Review: go run ./cmd/atde -mode caught")
	fmt.Println("Console: http://127.0.0.1:9091/console (with catch-node running)")
}

func watchCaught() {
	l := catch.New("./data/caught")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(os.Stderr, "watching data/caught/events.jsonl (ctrl+c to stop)\n")
	if err := l.Watch(ctx.Done(), os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "watch: %v\n", err)
		os.Exit(1)
	}
}

func runDoctor(cfg *config.Config) {
	checks := doctor.Run(cfg)
	fails := 0
	warns := 0
	for _, c := range checks {
		mark := "OK "
		if !c.OK {
			mark = "FAIL"
			fails++
		} else if c.Level == "warn" {
			mark = "WARN"
			warns++
		}
		line := fmt.Sprintf("[%s] %-18s %s", mark, c.Name, c.Detail)
		if c.Hint != "" {
			line += " — " + c.Hint
		}
		fmt.Println(line)
	}
	fmt.Printf("\nATDE doctor %s — %d checks, %d warn, %d fail\n", version, len(checks), warns, fails)
	fmt.Println("Next: make up   OR   go run ./cmd/atde -mode all")
	fmt.Println("Console: http://127.0.0.1:9091/console")
	os.Exit(doctor.ExitCode(checks))
}

func printStatus(cfg *config.Config) {
	l := catch.New("./data/caught")
	hits, uniq, _ := l.Summary()
	fmt.Printf("ATDE %s\n", version)
	fmt.Printf("  live=%v dry_run=%v local_fw=%v\n", cfg.App.Live, cfg.App.DryRun, cfg.ActiveDefense.Edge.LocalFirewall)
	fmt.Printf("  nats=%s ops=%s\n", cfg.NATS.URL, cfg.App.OpsAddr)
	fmt.Printf("  honeypot http=%s ssh=%s redis=%s telnet=%s mysql=%s ftp=%s smtp=%s es=%s mongo=%s deception=%s\n",
		cfg.Ingest.Honeypot.HTTPAddr, cfg.Ingest.Honeypot.SSHAddr,
		cfg.Ingest.Honeypot.RedisAddr, cfg.Ingest.Honeypot.TelnetAddr,
		cfg.Ingest.Honeypot.MySQLAddr, cfg.Ingest.Honeypot.FTPAddr,
		cfg.Ingest.Honeypot.SMTPAddr, cfg.Ingest.Honeypot.ESAddr, cfg.Ingest.Honeypot.MongoAddr,
		cfg.Deception.ListenAddr)
	fmt.Printf("  caught: %d hits / %d IPs\n", hits, uniq)
	fmt.Printf("  webhook=%v email=%v ops_token=%v\n",
		os.Getenv("ATDE_WEBHOOK_URL") != "",
		os.Getenv("ATDE_ALERT_TO") != "" || os.Getenv("ATDE_ALERT_EMAIL") != "" || os.Getenv("ATDE_OWNER_EMAIL") != "",
		os.Getenv("ATDE_OPS_TOKEN") != "")
	fmt.Printf("  console: http://127.0.0.1%s/console\n", normalizeAddr(cfg.App.OpsAddr))
}

func normalizeAddr(addr string) string {
	if addr == "" || addr == "off" {
		return ":9091"
	}
	return addr
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}