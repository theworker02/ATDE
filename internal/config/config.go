package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	App           AppConfig           `yaml:"app"`
	NATS          NATSConfig          `yaml:"nats"`
	Postgres      PostgresConfig      `yaml:"postgres"`
	Ingest        IngestConfig        `yaml:"ingest"`
	Extract       ExtractConfig       `yaml:"extract"`
	Trace         TraceConfig         `yaml:"trace"`
	Disrupt       DisruptConfig       `yaml:"disrupt"`
	ActiveDefense ActiveDefenseConfig `yaml:"active_defense"`
	Sinkhole      SinkholeConfig      `yaml:"sinkhole"`
	Publish       PublishConfig       `yaml:"publish"`
	Harden        HardenConfig        `yaml:"harden"`
	Deception     DeceptionConfig     `yaml:"deception"`
	Brands        []string            `yaml:"brands"`
}

type AppConfig struct {
	Name     string `yaml:"name"`
	Env      string `yaml:"env"`
	LogLevel string `yaml:"log_level"`
	DryRun   bool   `yaml:"dry_run"`
	Live     bool   `yaml:"live"` // when true, all owned-infra integrations execute for real
	OpsAddr  string `yaml:"ops_addr"` // health/metrics listen address
}

type NATSConfig struct {
	URL string `yaml:"url"`
}

type PostgresConfig struct {
	DSN     string `yaml:"dsn"`
	Enabled bool   `yaml:"enabled"`
}

type IngestConfig struct {
	CT       CTConfig       `yaml:"ct"`
	Honeypot HoneypotConfig `yaml:"honeypot"`
}

type CTConfig struct {
	Enabled   bool   `yaml:"enabled"`
	WSURL     string `yaml:"ws_url"`
	Workers   int    `yaml:"workers"`
	QueueSize int    `yaml:"queue_size"`
}

type HoneypotConfig struct {
	Enabled    bool   `yaml:"enabled"`
	HTTPAddr   string `yaml:"http_addr"`
	SSHAddr    string `yaml:"ssh_addr"`
	RedisAddr  string `yaml:"redis_addr"`  // e.g. ":6379" or "off"
	TelnetAddr string `yaml:"telnet_addr"` // e.g. ":2323" or "off"
	MySQLAddr  string `yaml:"mysql_addr"`  // e.g. ":3306" or "off" (1.3+)
	FTPAddr    string `yaml:"ftp_addr"`    // e.g. ":2121" or "off" (1.3+)
	SMTPAddr   string `yaml:"smtp_addr"`   // e.g. ":2525" or "off" (2.0+)
	ESAddr     string `yaml:"es_addr"`     // e.g. ":9200" or "off" (2.0+)
	MongoAddr  string `yaml:"mongo_addr"`  // e.g. ":27017" or "off" (2.0+)
	BlockAfter int    `yaml:"block_after"` // local FW after N public hits (0=off, default 3 in catch-node)
}

type ExtractConfig struct {
	WorkDir string        `yaml:"work_dir"`
	Timeout time.Duration `yaml:"timeout"`
}

type TraceConfig struct {
	ETHRPC  string `yaml:"eth_rpc"`
	MaxHops int    `yaml:"max_hops"`
}

type DisruptConfig struct {
	EvidenceDir   string            `yaml:"evidence_dir"`
	Channels      map[string]string `yaml:"channels"`
	MinConfidence float64           `yaml:"min_confidence"`
}

type ActiveDefenseConfig struct {
	Enabled       bool         `yaml:"enabled"`
	DryRun        bool         `yaml:"dry_run"`
	MinConfidence float64      `yaml:"min_confidence"`
	Tarpit        TarpitConfig `yaml:"tarpit"`
	Poison        PoisonConfig `yaml:"poison"`
	Edge          EdgeConfig   `yaml:"edge"`
}

type TarpitConfig struct {
	Enabled      bool          `yaml:"enabled"`
	ByteInterval time.Duration `yaml:"byte_interval"`
	MaxDuration  time.Duration `yaml:"max_duration"`
	MaxConns     int           `yaml:"max_conns"`
}

type PoisonConfig struct {
	Enabled   bool `yaml:"enabled"`
	BatchSize int  `yaml:"batch_size"`
}

type EdgeConfig struct {
	Enabled          bool   `yaml:"enabled"`
	DryRun           bool   `yaml:"dry_run"`
	LocalFirewall    bool   `yaml:"local_firewall"`
	CloudflareToken  string `yaml:"cloudflare_token"`
	CloudflareZoneID string `yaml:"cloudflare_zone_id"`
	AWSWAFEndpoint   string `yaml:"aws_waf_endpoint"`
	AWSIPSetID       string `yaml:"aws_waf_ipset_id"`
	AWSIPSetName     string `yaml:"aws_waf_ipset_name"`
	AWSRegion        string `yaml:"aws_region"`
	AWSCloudFront    bool   `yaml:"aws_waf_cloudfront"`
}

type SinkholeConfig struct {
	Enabled              bool   `yaml:"enabled"`
	DryRun               bool   `yaml:"dry_run"`
	SinkholeIP           string `yaml:"sinkhole_ip"`
	ListenAddr           string `yaml:"listen_addr"`
	CoreDNSAdminURL      string `yaml:"coredns_admin_url"`
	CloudflareGatewayURL string `yaml:"cloudflare_gateway_url"`
	EvidenceDir          string `yaml:"evidence_dir"`
}

type PublishConfig struct {
	Enabled          bool   `yaml:"enabled"`
	DryRun           bool   `yaml:"dry_run"`
	EvidenceDir      string `yaml:"evidence_dir"`
	AbuseIPDBKey     string `yaml:"abuseipdb_key"`
	MISPURL          string `yaml:"misp_url"`
	MISPKey          string `yaml:"misp_key"`
	MastodonToken    string `yaml:"mastodon_token"`
	MastodonInstance string `yaml:"mastodon_instance"`
	BlueskyWebhook   string `yaml:"bluesky_webhook"`
	GitHubToken      string `yaml:"github_token"`
}

// HardenConfig controls compile/runtime anti-analysis (production nodes).
type HardenConfig struct {
	Enabled         bool          `yaml:"enabled"`
	HardMode        bool          `yaml:"hard_mode"` // SIGKILL on trip; soft only zeroizes
	AntiDebug       bool          `yaml:"anti_debug"`
	TimingCheck     bool          `yaml:"timing_check"`
	TimingThreshold time.Duration `yaml:"timing_threshold"`
	IntegrityCheck  bool          `yaml:"integrity_check"`
	DisableDumpable bool          `yaml:"disable_dumpable"`
	Seccomp         bool          `yaml:"seccomp"`
	WatchInterval   time.Duration `yaml:"watch_interval"`
}

// DeceptionConfig is the asymmetric L7 honey-interface proxy.
type DeceptionConfig struct {
	Enabled         bool          `yaml:"enabled"`
	ListenAddr      string        `yaml:"listen_addr"`
	UpstreamURL     string        `yaml:"upstream_url"`
	DecoyThreshold  int           `yaml:"decoy_threshold"`
	MaxDelay        time.Duration `yaml:"max_delay"`
	DryRun          bool          `yaml:"dry_run"`
	SIEMWebhook     string        `yaml:"siem_webhook"`
	TrustedProxies  []string      `yaml:"trusted_proxies"`
	CloudflareToken string        `yaml:"cloudflare_token"`
	CloudflareZone  string        `yaml:"cloudflare_zone_id"`
	AWSRegion       string        `yaml:"aws_region"`
	AWSIPSetID      string        `yaml:"aws_waf_ipset_id"`
	AWSIPSetName    string        `yaml:"aws_waf_ipset_name"`
	AWSCloudFront   bool          `yaml:"aws_waf_cloudfront"`
	WAFWebhook      string        `yaml:"waf_block_webhook"`
	AutoBlockScore  int           `yaml:"auto_block_score"`
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal([]byte(os.ExpandEnv(string(raw))), &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.App.Name == "" {
		c.App.Name = "atde"
	}
	if c.App.LogLevel == "" {
		c.App.LogLevel = "info"
	}
	if c.App.OpsAddr == "" {
		c.App.OpsAddr = ":9091"
	}
	if c.App.Env == "" {
		c.App.Env = "dev"
	}

	// Live mode: ATDE_LIVE=1|true|yes OR app.live: true OR (env=production AND dry_run not forced)
	// ATDE_DRY_RUN=1 forces simulation regardless.
	live := c.App.Live || envTruthy("ATDE_LIVE") ||
		(strings.EqualFold(c.App.Env, "production") && !envTruthy("ATDE_DRY_RUN"))
	if envTruthy("ATDE_DRY_RUN") {
		live = false
	}
	c.App.Live = live
	c.App.DryRun = !live

	if c.NATS.URL == "" {
		c.NATS.URL = "nats://127.0.0.1:4222"
	}
	if c.Ingest.CT.WSURL == "" {
		c.Ingest.CT.WSURL = "wss://certstream.calidog.io/"
	}
	if c.Ingest.CT.Workers == 0 {
		c.Ingest.CT.Workers = 10
	}
	if c.Ingest.CT.QueueSize == 0 {
		c.Ingest.CT.QueueSize = 5000
	}
	if c.Ingest.Honeypot.HTTPAddr == "" {
		c.Ingest.Honeypot.HTTPAddr = ":8080"
	}
	if c.Ingest.Honeypot.SSHAddr == "" {
		c.Ingest.Honeypot.SSHAddr = ":2222"
	}
	if c.Ingest.Honeypot.RedisAddr == "" {
		c.Ingest.Honeypot.RedisAddr = ":6379"
	}
	if c.Ingest.Honeypot.TelnetAddr == "" {
		c.Ingest.Honeypot.TelnetAddr = ":2323"
	}
	if c.Ingest.Honeypot.MySQLAddr == "" {
		c.Ingest.Honeypot.MySQLAddr = ":3306"
	}
	if c.Ingest.Honeypot.FTPAddr == "" {
		c.Ingest.Honeypot.FTPAddr = ":2121"
	}
	if c.Ingest.Honeypot.SMTPAddr == "" {
		c.Ingest.Honeypot.SMTPAddr = ":2525"
	}
	if c.Ingest.Honeypot.ESAddr == "" {
		c.Ingest.Honeypot.ESAddr = ":9200"
	}
	if c.Ingest.Honeypot.MongoAddr == "" {
		c.Ingest.Honeypot.MongoAddr = ":27017"
	}
	if c.Extract.WorkDir == "" {
		c.Extract.WorkDir = "./data/sandbox"
	}
	if c.Extract.Timeout == 0 {
		c.Extract.Timeout = 2 * time.Minute
	}
	if c.Trace.ETHRPC == "" {
		c.Trace.ETHRPC = "https://eth.llamarpc.com"
	}
	if c.Trace.MaxHops == 0 {
		c.Trace.MaxHops = 3
	}
	if c.Disrupt.EvidenceDir == "" {
		c.Disrupt.EvidenceDir = "./data/evidence"
	}
	if c.Disrupt.MinConfidence == 0 {
		c.Disrupt.MinConfidence = 0.7
	}

	if c.ActiveDefense.MinConfidence == 0 {
		c.ActiveDefense.MinConfidence = 0.7
	}
	if !c.ActiveDefense.Enabled {
		c.ActiveDefense.Enabled = true
	}
	if c.ActiveDefense.Tarpit.ByteInterval == 0 {
		c.ActiveDefense.Tarpit.ByteInterval = 5 * time.Second
	}
	if c.ActiveDefense.Tarpit.MaxDuration == 0 {
		c.ActiveDefense.Tarpit.MaxDuration = 30 * time.Minute
	}
	if c.ActiveDefense.Tarpit.MaxConns == 0 {
		c.ActiveDefense.Tarpit.MaxConns = 256
	}
	c.ActiveDefense.Tarpit.Enabled = true
	c.ActiveDefense.Poison.Enabled = true // evidence-only channel; never live third-party flood
	c.ActiveDefense.Edge.Enabled = true
	if c.ActiveDefense.Poison.BatchSize == 0 {
		c.ActiveDefense.Poison.BatchSize = 100
	}

	c.Sinkhole.Enabled = true
	c.Publish.Enabled = true
	c.Deception.Enabled = true

	if c.Sinkhole.SinkholeIP == "" {
		c.Sinkhole.SinkholeIP = "127.0.0.1"
	}
	if c.Sinkhole.ListenAddr == "" {
		c.Sinkhole.ListenAddr = ":9080"
	}
	if c.Sinkhole.EvidenceDir == "" {
		c.Sinkhole.EvidenceDir = c.Disrupt.EvidenceDir
	}
	if c.Publish.EvidenceDir == "" {
		c.Publish.EvidenceDir = c.Disrupt.EvidenceDir
	}

	if c.Harden.WatchInterval == 0 {
		c.Harden.WatchInterval = 2 * time.Second
	}
	if c.Harden.TimingThreshold == 0 {
		c.Harden.TimingThreshold = 500 * time.Millisecond
	}
	if live && c.Harden.Enabled {
		c.Harden.AntiDebug = true
		c.Harden.DisableDumpable = true
		c.Harden.Seccomp = true
	}
	if !live {
		c.Harden.HardMode = false
	}

	if c.Deception.ListenAddr == "" {
		c.Deception.ListenAddr = ":8443"
	}
	if c.Deception.DecoyThreshold == 0 {
		c.Deception.DecoyThreshold = 25
	}
	if c.Deception.MaxDelay == 0 {
		c.Deception.MaxDelay = 15 * time.Second
	}
	if c.Deception.AutoBlockScore == 0 {
		c.Deception.AutoBlockScore = 50
	}

	// Cascade live/dry-run to every owned-infra subsystem (YAML flags are overridden by app.live).
	c.ActiveDefense.DryRun = !live
	c.ActiveDefense.Edge.DryRun = !live
	c.Sinkhole.DryRun = !live
	c.Publish.DryRun = !live
	c.Deception.DryRun = !live
	if live {
		// Catch hackers without cloud APIs: local firewall on by default in live mode.
		c.ActiveDefense.Edge.LocalFirewall = true
		if envTruthy("ATDE_LOCAL_FIREWALL") {
			c.ActiveDefense.Edge.LocalFirewall = true
		}
		if envFalsy("ATDE_LOCAL_FIREWALL") {
			c.ActiveDefense.Edge.LocalFirewall = false
		}
	}

	c.hydrateSecretsFromEnv()

	if len(c.Brands) == 0 {
		c.Brands = []string{
			"chase", "paypal", "binance", "coinbase", "metamask",
			"wellsfargo", "appleid", "bankofamerica", "phantom", "trustwallet",
			"microsoft", "google", "amazon",
		}
	}
}

func (c *Config) hydrateSecretsFromEnv() {
	c.ActiveDefense.Edge.CloudflareToken = firstNonEmpty(c.ActiveDefense.Edge.CloudflareToken, os.Getenv("CLOUDFLARE_API_TOKEN"))
	c.ActiveDefense.Edge.CloudflareZoneID = firstNonEmpty(c.ActiveDefense.Edge.CloudflareZoneID, os.Getenv("CLOUDFLARE_ZONE_ID"))
	c.ActiveDefense.Edge.AWSWAFEndpoint = firstNonEmpty(c.ActiveDefense.Edge.AWSWAFEndpoint, os.Getenv("AWS_WAF_BLOCK_ENDPOINT"), os.Getenv("WAF_BLOCK_WEBHOOK"))
	c.ActiveDefense.Edge.AWSIPSetID = firstNonEmpty(c.ActiveDefense.Edge.AWSIPSetID, os.Getenv("AWS_WAF_IPSET_ID"))
	c.ActiveDefense.Edge.AWSIPSetName = firstNonEmpty(c.ActiveDefense.Edge.AWSIPSetName, os.Getenv("AWS_WAF_IPSET_NAME"))
	c.ActiveDefense.Edge.AWSRegion = firstNonEmpty(c.ActiveDefense.Edge.AWSRegion, os.Getenv("AWS_REGION"), os.Getenv("AWS_DEFAULT_REGION"))

	c.Deception.CloudflareToken = firstNonEmpty(c.Deception.CloudflareToken, os.Getenv("CLOUDFLARE_API_TOKEN"))
	c.Deception.CloudflareZone = firstNonEmpty(c.Deception.CloudflareZone, os.Getenv("CLOUDFLARE_ZONE_ID"))
	c.Deception.AWSIPSetID = firstNonEmpty(c.Deception.AWSIPSetID, os.Getenv("AWS_WAF_IPSET_ID"))
	c.Deception.AWSIPSetName = firstNonEmpty(c.Deception.AWSIPSetName, os.Getenv("AWS_WAF_IPSET_NAME"))
	c.Deception.AWSRegion = firstNonEmpty(c.Deception.AWSRegion, os.Getenv("AWS_REGION"), os.Getenv("AWS_DEFAULT_REGION"))
	c.Deception.WAFWebhook = firstNonEmpty(c.Deception.WAFWebhook, os.Getenv("WAF_BLOCK_WEBHOOK"), os.Getenv("AWS_WAF_BLOCK_ENDPOINT"))
	c.Deception.SIEMWebhook = firstNonEmpty(c.Deception.SIEMWebhook, os.Getenv("SIEM_WEBHOOK_URL"))
	c.Deception.AWSCloudFront = c.Deception.AWSCloudFront || strings.EqualFold(os.Getenv("AWS_WAF_SCOPE"), "CLOUDFRONT")
	c.ActiveDefense.Edge.AWSCloudFront = c.ActiveDefense.Edge.AWSCloudFront || strings.EqualFold(os.Getenv("AWS_WAF_SCOPE"), "CLOUDFRONT")

	c.Sinkhole.CoreDNSAdminURL = firstNonEmpty(c.Sinkhole.CoreDNSAdminURL, os.Getenv("COREDNS_REWRITE_API"))
	c.Sinkhole.CloudflareGatewayURL = firstNonEmpty(c.Sinkhole.CloudflareGatewayURL, os.Getenv("CF_GATEWAY_REWRITE_URL"))

	c.Publish.AbuseIPDBKey = firstNonEmpty(c.Publish.AbuseIPDBKey, os.Getenv("ABUSEIPDB_API_KEY"))
	c.Publish.MISPURL = firstNonEmpty(c.Publish.MISPURL, os.Getenv("MISP_URL"))
	c.Publish.MISPKey = firstNonEmpty(c.Publish.MISPKey, os.Getenv("MISP_API_KEY"))
	c.Publish.MastodonToken = firstNonEmpty(c.Publish.MastodonToken, os.Getenv("MASTODON_ACCESS_TOKEN"))
	c.Publish.MastodonInstance = firstNonEmpty(c.Publish.MastodonInstance, os.Getenv("MASTODON_INSTANCE_URL"))
	c.Publish.BlueskyWebhook = firstNonEmpty(c.Publish.BlueskyWebhook, os.Getenv("BLUESKY_POST_WEBHOOK"))
	c.Publish.GitHubToken = firstNonEmpty(c.Publish.GitHubToken, os.Getenv("GITHUB_TOKEN"))
}

func envTruthy(k string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(k)))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func envFalsy(k string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(k)))
	return v == "0" || v == "false" || v == "no" || v == "off"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func SeverityAtLeast(sev, min string) bool {
	rank := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	return rank[strings.ToLower(sev)] >= rank[strings.ToLower(min)]
}
