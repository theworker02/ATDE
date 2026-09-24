package fingerprint

// MITRE ATT&CK technique IDs commonly observed on decoy surfaces (defensive mapping).
func TechniquesFor(tags []string, service, tool string) []string {
	seen := map[string]struct{}{}
	add := func(ids ...string) {
		for _, id := range ids {
			seen[id] = struct{}{}
		}
	}
	add("T1595") // Active Scanning — always for honeypot hits
	svc := service
	for _, t := range tags {
		switch t {
		case "cred-spray", "ssh-auth-burn", "ftp-bait", "telnet-bait":
			add("T1110", "T1110.001") // Brute Force / Password Guessing
		case "auth-burn":
			add("T1110")
		case "vuln-bait", "rce-bait":
			add("T1190", "T1595.002") // Exploit Public-Facing / Vulnerability Scanning
		case "sqli":
			add("T1190", "T1059")
		case "xss":
			add("T1059.007")
		case "redis-exploit", "redis-bait":
			add("T1190", "T1059")
		case "mysql-bait", "db-scan":
			add("T1190", "T1078")
		case "iot-botnet":
			add("T1110", "T1583.005")
		case "scanner", "recon":
			add("T1595.001")
		case "secrets_hunt", "secrets-hunt":
			add("T1552", "T1083")
		}
	}
	switch {
	case containsFold(svc, "ssh"):
		add("T1110", "T1021.004")
	case containsFold(svc, "smtp"):
		add("T1110", "T1598")
	case containsFold(svc, "mongo"), containsFold(svc, "elastic"):
		add("T1190", "T1213")
	case containsFold(tool, "sqlmap"):
		add("T1190", "T1059")
	case containsFold(tool, "nuclei"):
		add("T1595.002")
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sortStrings(out)
	return out
}

func containsFold(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		indexFold(s, sub) >= 0)
}

func indexFold(s, sub string) int {
	sl, subl := toLower(s), toLower(sub)
	for i := 0; i+len(subl) <= len(sl); i++ {
		if sl[i:i+len(subl)] == subl {
			return i
		}
	}
	return -1
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func sortStrings(a []string) {
	for i := 0; i < len(a); i++ {
		for j := i + 1; j < len(a); j++ {
			if a[j] < a[i] {
				a[i], a[j] = a[j], a[i]
			}
		}
	}
}
