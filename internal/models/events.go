package models

import "time"

// NATS subject hierarchy for THREAT_PIPELINE.
const (
	SubjectRawCT         = "threat.v1.raw.ct"
	SubjectRawHoneypot   = "threat.v1.raw.honeypot"
	SubjectExtracted     = "threat.v1.artifact.extracted"
	SubjectTakedown      = "threat.v1.action.takedown"
	SubjectDisrupt       = "threat.v1.action.disrupt"
	SubjectSinkhole      = "threat.v1.action.sinkhole"
	SubjectPublish       = "threat.v1.action.publish"
	SubjectCompromised   = "threat.v1.action.compromised"
	SubjectAttack        = "threat.v1.artifact.attack"
	SubjectDLQ           = "threat.v1.action.dlq"
	StreamName           = "THREAT_PIPELINE"
)

// Disruption actions for Phase 4 active defense (in-bound / owned-edge only).
const (
	DisruptActionBlock  = "block"
	DisruptActionTarpit = "tarpit"
	DisruptActionPoison = "poison" // simulated / evidence-only; no third-party API abuse
)

// RawCTEvent is published on threat.v1.raw.ct.
type RawCTEvent struct {
	ID          string    `json:"id"`
	Schema      string    `json:"$schema,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
	Source      string    `json:"source"`
	Data        CTData    `json:"data"`
	MatchedRule string    `json:"matched_rule,omitempty"`
}

type CTData struct {
	Fingerprint string   `json:"fingerprint,omitempty"`
	Domain      string   `json:"domain"`
	AllDomains  []string `json:"all_domains"`
	Issuer      string   `json:"issuer,omitempty"`
	SeenAt      int64    `json:"seen_at"`
}

// RawHoneypotEvent is published on threat.v1.raw.honeypot.
type RawHoneypotEvent struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	Source    string            `json:"source"`
	Data      HoneypotData      `json:"data"`
}

type HoneypotData struct {
	Service    string            `json:"service"`
	RemoteAddr string            `json:"remote_addr"`
	Path       string            `json:"path,omitempty"`
	Method     string            `json:"method,omitempty"`
	UserAgent  string            `json:"user_agent,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	BodyB64    string            `json:"body_b64,omitempty"`
}

// ExtractedIOCs holds isolated indicators.
type ExtractedIOCs struct {
	TelegramBotTokens []string `json:"telegram_bot_tokens,omitempty"`
	TelegramChatIDs   []string `json:"telegram_chat_ids,omitempty"`
	ExfilEndpoints    []string `json:"exfil_endpoints,omitempty"`
	DropIPs           []string `json:"drop_ips,omitempty"`
	WalletsBTC        []string `json:"wallets_btc,omitempty"`
	WalletsETH        []string `json:"wallets_eth,omitempty"`
	WalletsSOL        []string `json:"wallets_sol,omitempty"`
	Webhooks          []string `json:"webhooks,omitempty"`
}

// ArtifactExtracted is published on threat.v1.artifact.extracted.
type ArtifactExtracted struct {
	ID              string        `json:"id"`
	ParentID        string        `json:"parent_id"`
	Timestamp       time.Time     `json:"timestamp"`
	ThreatType      string        `json:"threat_type"`
	TargetBrand     string        `json:"target_brand,omitempty"`
	TargetDomain    string        `json:"target_domain"`
	ExtractedIOCs   ExtractedIOCs `json:"extracted_iocs"`
	ConfidenceScore float64       `json:"confidence_score"`
	Snippets        []string      `json:"snippets,omitempty"`
}

// TakedownTarget describes infrastructure to neutralize.
type TakedownTarget struct {
	Domain          string `json:"domain"`
	IP              string `json:"ip,omitempty"`
	ASN             string `json:"asn,omitempty"`
	Registrar       string `json:"registrar,omitempty"`
	HostingProvider string `json:"hosting_provider,omitempty"`
}

// EvidenceSummary is included in abuse packages.
type EvidenceSummary struct {
	Title              string `json:"title"`
	HarvesterURL       string `json:"harvester_url,omitempty"`
	ExfiltrationMethod string `json:"exfiltration_method,omitempty"`
	PCAPHashSHA256     string `json:"pcap_hash_sha256,omitempty"`
}

// TakedownEvent is published on threat.v1.action.takedown.
type TakedownEvent struct {
	ID              string          `json:"id"`
	ArtifactID      string          `json:"artifact_id"`
	Timestamp       time.Time       `json:"timestamp"`
	Target          TakedownTarget  `json:"target"`
	EvidenceSummary EvidenceSummary `json:"evidence_summary"`
	DispatchTargets []string        `json:"dispatch_targets"`
	DryRun          bool            `json:"dry_run,omitempty"`
}

// DLQEvent captures failed/unparseable payloads.
type DLQEvent struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Subject   string    `json:"subject"`
	Error     string    `json:"error"`
	Payload   string    `json:"payload,omitempty"`
}

// DisruptionEvent is published on threat.v1.action.disrupt.
type DisruptionEvent struct {
	ID         string         `json:"id"`
	ParentID   string         `json:"parent_id,omitempty"`
	Timestamp  time.Time      `json:"timestamp"`
	SourceIP   string         `json:"source_ip,omitempty"`
	Reason     string         `json:"reason"`
	Action     string         `json:"action"` // block | tarpit | poison
	Target     string         `json:"target,omitempty"`
	Channels   []string       `json:"channels,omitempty"`
	Meta       map[string]any `json:"meta,omitempty"`
	DryRun     bool           `json:"dry_run,omitempty"`
	Simulated  bool           `json:"simulated,omitempty"` // true when action is evidence-only
}

// SinkholeEvent is published on threat.v1.action.sinkhole.
type SinkholeEvent struct {
	ID         string   `json:"id"`
	ParentID   string   `json:"parent_id,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
	BotnetName string   `json:"botnet_name"`
	C2Domains  []string `json:"c2_domains"`
	C2IPs      []string `json:"c2_ips"`
	Protocol   string   `json:"protocol"` // http | p2p_dht | p2p | irc
	SinkholeIP string   `json:"sinkhole_ip"`
	DryRun     bool     `json:"dry_run,omitempty"`
}

// PublishEvent is published on threat.v1.action.publish.
type PublishEvent struct {
	ID                 string   `json:"id"`
	ParentID           string   `json:"parent_id,omitempty"`
	Timestamp          time.Time `json:"timestamp"`
	ThreatType         string   `json:"threat_type"`
	TargetDomain       string   `json:"target_domain"`
	AttackerIP         string   `json:"attacker_ip"`
	AbuseIPDBCategories []int   `json:"abuseipdb_categories"`
	IOCs               []string `json:"iocs"`
	Summary            string   `json:"summary"`
	Channels           []string `json:"channels,omitempty"`
	DryRun             bool     `json:"dry_run,omitempty"`
}

// CompromisedEvent is published when a node detects reverse-engineering / tampering.
type CompromisedEvent struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Hostname  string    `json:"hostname"`
	PID       int       `json:"pid"`
	Reason    string    `json:"reason"`
	BuildSig  string    `json:"build_signature,omitempty"`
	Mode      string    `json:"mode"` // soft | hard
}

// AttackEvent is high-fidelity deception telemetry (Rule 2: Recorder).
type AttackEvent struct {
	ID             string            `json:"id"`
	Timestamp      time.Time         `json:"timestamp"`
	ClientIP       string            `json:"client_ip"`
	IPSource       string            `json:"ip_source"` // remote_addr | xff | cf-connecting-ip
	UserAgent      string            `json:"user_agent"`
	TargetEndpoint string            `json:"target_endpoint"`
	Method         string            `json:"method"`
	VulnClass      string            `json:"vuln_class"`
	RawPayload     string            `json:"raw_payload"`
	HTTPHeaders    map[string]string `json:"http_headers"`
	JA3            string            `json:"ja3,omitempty"`
	JA4            string            `json:"ja4,omitempty"`
	ToolHint       string            `json:"tool_hint,omitempty"`
	RiskScore      int               `json:"risk_score"`
	Timeline       []AttackBeat      `json:"timeline,omitempty"`
}

// AttackBeat is one step in a session behavioral timeline.
type AttackBeat struct {
	At       time.Time `json:"at"`
	Path     string    `json:"path"`
	VulnClass string   `json:"vuln_class,omitempty"`
	DeltaMS  int64     `json:"delta_ms"`
}
