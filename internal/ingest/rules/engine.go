package rules

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode"
)

// Engine performs high-speed brand / phishing / token heuristics on domains.
type Engine struct {
	brandRegex     *regexp.Regexp
	suspiciousReg  *regexp.Regexp
	exfilRegex     *regexp.Regexp
	punycodeReg    *regexp.Regexp
	digitHomoglyph *regexp.Regexp
	brands         []string
}

func New(brands []string) *Engine {
	brandPattern := `(?i)(` + strings.Join(escapeAlts(brands), "|") + `)`
	suspiciousPattern := `(?i)(login|verify|update|secure|account|wallet|auth|signin|support|portal|confirm|recovery|security|validation)[-.]`
	exfilPattern := `(?i)(\d{8,10}:[A-Za-z0-9_-]{35}|0x[a-fA-F0-9]{40})`
	return &Engine{
		brandRegex:     regexp.MustCompile(brandPattern),
		suspiciousReg:  regexp.MustCompile(suspiciousPattern),
		exfilRegex:     regexp.MustCompile(exfilPattern),
		punycodeReg:    regexp.MustCompile(`(?i)^xn--`),
		digitHomoglyph: regexp.MustCompile(`(?i)(paypa1|g00gle|micr0soft|app1e|amaz0n|faceb00k|c0inbase|binancee)`),
		brands:         brands,
	}
}

func escapeAlts(brands []string) []string {
	out := make([]string, 0, len(brands))
	for _, b := range brands {
		b = strings.TrimSpace(b)
		if b == "" {
			continue
		}
		out = append(out, regexp.QuoteMeta(b))
	}
	if len(out) == 0 {
		return []string{"paypal", "chase"}
	}
	return out
}

// Score is a structured assessment used by CT and diligence demos.
type Score struct {
	Suspicious bool     `json:"suspicious"`
	Score      float64  `json:"score"` // 0..1
	Rule       string   `json:"rule,omitempty"`
	Brand      string   `json:"brand,omitempty"`
	Signals    []string `json:"signals,omitempty"`
}

// InspectDomain returns whether the domain is suspicious and the matched rule.
func (re *Engine) InspectDomain(domain string) (bool, string) {
	s := re.Assess(domain)
	return s.Suspicious, s.Rule
}

// Assess applies layered heuristics (brand+keyword, IDN, homoglyph, entropy, depth).
func (re *Engine) Assess(domain string) Score {
	domain = strings.TrimPrefix(strings.ToLower(domain), "*.")
	domain = strings.TrimSuffix(domain, ".")
	var signals []string
	score := 0.0
	brand := re.DetectBrand(domain)
	rule := ""

	if brand != "" {
		signals = append(signals, "brand_substring:"+brand)
		score += 0.35
	}
	if re.suspiciousReg.MatchString(domain) {
		signals = append(signals, "phishing_keyword")
		score += 0.35
	}
	if brand != "" && re.suspiciousReg.MatchString(domain) {
		rule = "Brand Impersonation + Phishing Keyword"
		score += 0.2
	}
	if re.exfilRegex.MatchString(domain) {
		signals = append(signals, "embedded_token_pattern")
		score += 0.5
		if rule == "" {
			rule = "Embedded Credential/Token Pattern"
		}
	}
	for _, lab := range strings.Split(domain, ".") {
		if re.punycodeReg.MatchString(lab) {
			signals = append(signals, "punycode_label")
			score += 0.25
			if rule == "" {
				rule = "IDN / Punycode Lure"
			}
		}
	}
	if re.digitHomoglyph.MatchString(domain) {
		signals = append(signals, "digit_homoglyph")
		score += 0.4
		if rule == "" {
			rule = "Homoglyph Brand Impersonation"
		}
	}
	if brand != "" && looksLikeTyposquat(domain, brand) {
		signals = append(signals, "typosquat_distance")
		score += 0.3
		if rule == "" {
			rule = "Brand Typosquat"
		}
	}
	if labelCount(domain) >= 4 {
		signals = append(signals, "deep_subdomain")
		score += 0.1
	}
	if hyphenDensity(domain) >= 3 {
		signals = append(signals, "hyphen_stuffing")
		score += 0.1
	}
	labels := strings.Split(domain, ".")
	if len(labels) > 0 && shannonHint(labels[0]) > 3.8 && len(labels[0]) > 16 {
		signals = append(signals, "high_entropy_label")
		score += 0.15
	}

	if score > 1 {
		score = 1
	}
	suspicious := score >= 0.55 || rule != ""
	if suspicious && rule == "" {
		rule = "Heuristic Risk Score"
	}
	return Score{Suspicious: suspicious, Score: score, Rule: rule, Brand: brand, Signals: signals}
}

// DetectBrand returns the first brand substring found in domain.
func (re *Engine) DetectBrand(domain string) string {
	lower := strings.ToLower(domain)
	for _, b := range re.brands {
		if strings.Contains(lower, strings.ToLower(b)) {
			return strings.ToLower(b)
		}
	}
	folded := foldLeet(lower)
	for _, b := range re.brands {
		if strings.Contains(folded, strings.ToLower(b)) {
			return strings.ToLower(b)
		}
	}
	return ""
}

// ThreatTypeFromRule maps rule names to artifact threat types.
func ThreatTypeFromRule(rule string) string {
	switch {
	case strings.Contains(rule, "Brand"), strings.Contains(rule, "Typosquat"), strings.Contains(rule, "Homoglyph"):
		return "phishing_credential_harvester"
	case strings.Contains(rule, "Token"):
		return "token_exfil_lure"
	case strings.Contains(rule, "IDN"), strings.Contains(rule, "Punycode"):
		return "idn_phishing_lure"
	default:
		return "suspicious_domain"
	}
}

func FormatBrandLabel(brand string) string {
	if brand == "" {
		return ""
	}
	return fmt.Sprintf("%s", strings.ReplaceAll(brand, " ", "_"))
}

func foldLeet(s string) string {
	repl := strings.NewReplacer(
		"0", "o", "1", "l", "3", "e", "4", "a", "5", "s", "7", "t", "@", "a",
	)
	return repl.Replace(s)
}

func looksLikeTyposquat(domain, brand string) bool {
	host := strings.Split(domain, ".")[0]
	host = strings.ReplaceAll(host, "-", "")
	b := strings.ReplaceAll(brand, "-", "")
	if b == "" || len(host) < len(b) {
		return false
	}
	for i := 0; i+len(b) <= len(host); i++ {
		window := host[i : i+len(b)]
		if window != b && levenshtein(window, b) <= 1 {
			return true
		}
	}
	return false
}

func levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	ra, rb := []rune(a), []rune(b)
	if len(ra) == 0 {
		return len(rb)
	}
	if len(rb) == 0 {
		return len(ra)
	}
	prev := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i, ca := range ra {
		cur := make([]int, len(rb)+1)
		cur[0] = i + 1
		for j, cb := range rb {
			cost := 0
			if ca != cb {
				cost = 1
			}
			cur[j+1] = min3(prev[j+1]+1, cur[j]+1, prev[j]+cost)
		}
		prev = cur
	}
	return prev[len(rb)]
}

func min3(a, b, c int) int {
	if a <= b && a <= c {
		return a
	}
	if b <= c {
		return b
	}
	return c
}

func labelCount(domain string) int {
	n := 0
	for _, p := range strings.Split(domain, ".") {
		if p != "" {
			n++
		}
	}
	return n
}

func hyphenDensity(domain string) int {
	return strings.Count(domain, "-")
}

func shannonHint(label string) float64 {
	if label == "" {
		return 0
	}
	var freq [256]int
	n := 0
	for _, r := range label {
		if r > 255 || unicode.IsSpace(r) {
			continue
		}
		freq[byte(r)]++
		n++
	}
	if n == 0 {
		return 0
	}
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / float64(n)
		h += -p * math.Log2(p)
	}
	return h
}
