package indicators

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// Extract scans raw payload bytes for high-signal exfil / C2 artifacts.
func Extract(raw []byte) (language string, inds []Indicator, snippets []string) {
	text := string(raw)
	language = detectLanguage(text)

	type rule struct {
		typ        string
		re         *regexp.Regexp
		confidence float64
	}
	rules := []rule{
		{"telegram_token", regexp.MustCompile(`\b(\d{8,10}:[A-Za-z0-9_-]{30,45})\b`), 0.95},
		{"telegram_chat", regexp.MustCompile(`(?i)(?:chat[_-]?id|CHATID)["'\s:=]+(-?\d{5,15})`), 0.85},
		{"webhook_discord", regexp.MustCompile(`https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+`), 0.95},
		{"webhook_slack", regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+`), 0.95},
		{"wallet_btc", regexp.MustCompile(`\b([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,62})\b`), 0.8},
		{"wallet_eth", regexp.MustCompile(`\b(0x[a-fA-F0-9]{40})\b`), 0.85},
		{"wallet_sol", regexp.MustCompile(`\b([1-9A-HJ-NP-Za-km-z]{32,44})\b`), 0.55}, // lower confidence — base58 noise
		{"c2_url", regexp.MustCompile(`(?i)https?://[a-z0-9.-]+\.[a-z]{2,}(?::\d{2,5})?(?:/[^\s"'<>]*)?`), 0.7},
		{"c2_ip", regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`), 0.65},
	}

	seen := map[string]struct{}{}
	for _, r := range rules {
		matches := r.re.FindAllStringSubmatch(text, -1)
		for _, m := range matches {
			val := m[0]
			if len(m) > 1 && m[1] != "" {
				val = m[1]
			}
			val = strings.TrimSpace(val)
			if val == "" {
				continue
			}
			if r.typ == "wallet_sol" && !looksLikeSol(val) {
				continue
			}
			if r.typ == "c2_ip" && isPrivateIP(val) {
				continue
			}
			key := r.typ + "|" + val
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			inds = append(inds, Indicator{
				Type:       r.typ,
				Value:      val,
				Confidence: r.confidence,
				Context:    clipContext(text, val, 80),
			})
		}
	}

	// Capture short snippets around high-confidence hits for evidence packs.
	for _, ind := range inds {
		if ind.Confidence >= 0.85 && len(snippets) < 8 {
			snippets = append(snippets, clipContext(text, ind.Value, 160))
		}
	}
	return language, inds, snippets
}

// Indicator mirrors models.Indicator without importing models (keep extract pure).
type Indicator struct {
	Type       string
	Value      string
	Confidence float64
	Context    string
}

func SHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func detectLanguage(text string) string {
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "<?php"):
		return "php"
	case strings.Contains(lower, "powershell") || strings.Contains(lower, "invoke-"):
		return "powershell"
	case strings.Contains(lower, "#!/bin/bash") || strings.Contains(lower, "curl ") && strings.Contains(lower, "| sh"):
		return "bash"
	case strings.Contains(lower, "function(") || strings.Contains(lower, "document.") || strings.Contains(lower, "eval("):
		return "javascript"
	default:
		return "unknown"
	}
}

func clipContext(text, needle string, pad int) string {
	idx := strings.Index(text, needle)
	if idx < 0 {
		return ""
	}
	start := idx - pad
	if start < 0 {
		start = 0
	}
	end := idx + len(needle) + pad
	if end > len(text) {
		end = len(text)
	}
	snip := text[start:end]
	snip = strings.ReplaceAll(snip, "\n", " ")
	snip = strings.ReplaceAll(snip, "\r", " ")
	return snip
}

func looksLikeSol(s string) bool {
	if len(s) < 32 || len(s) > 44 {
		return false
	}
	// Exclude pure hex eth-like and obvious words
	if strings.HasPrefix(s, "0x") {
		return false
	}
	return true
}

func isPrivateIP(ip string) bool {
	return strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "127.") ||
		strings.HasPrefix(ip, "0.") ||
		strings.HasPrefix(ip, "169.254.") ||
		(strings.HasPrefix(ip, "172.") && private172(ip))
}

func private172(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) < 2 {
		return false
	}
	var n int
	for _, c := range parts[1] {
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n >= 16 && n <= 31
}

// DecodeLight applies common obfuscation reversals without executing code.
func DecodeLight(raw []byte) []byte {
	text := string(raw)
	// Concatenate common JS string-split patterns already present as plaintext after minify undoing is out of scope.
	// Base64 blobs longer than 40 chars: leave as-is but append decoded attempts for scanning.
	re := regexp.MustCompile(`(?i)(?:atob|base64_decode|FromBase64String)\(['"]([A-Za-z0-9+/=]{40,})['"]\)`)
	out := text
	for _, m := range re.FindAllStringSubmatch(text, 20) {
		if dec, err := decodeB64(m[1]); err == nil && len(dec) > 0 {
			out += "\n" + string(dec)
		}
	}
	return []byte(out)
}

func decodeB64(s string) ([]byte, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	// use std encoding via thin wrapper to avoid import cycle noise — import encoding/base64
	return b64Decode(s)
}
