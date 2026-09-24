package fingerprint

import (
	"net/http"
	"testing"
)

func TestFromHTTPCredAndSQLi(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "http://x/login", nil)
	req.Header.Set("User-Agent", "sqlmap/1.7")
	r := FromHTTP(req, "username=admin&password=' OR 1=1--")
	if r.Severity < 80 {
		t.Fatalf("severity %d", r.Severity)
	}
	if r.Tool != "sqlmap" {
		t.Fatalf("tool %s", r.Tool)
	}
}

func TestFromServiceRedis(t *testing.T) {
	r := FromService("redis-bait", "", "CONFIG SET dir /var/www")
	if r.Severity < 85 {
		t.Fatalf("sev %d", r.Severity)
	}
}
