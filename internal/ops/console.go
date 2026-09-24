package ops

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/theworker02/ATDE/v2/internal/campaign"
	"github.com/theworker02/ATDE/v2/internal/catch"
	"github.com/theworker02/ATDE/v2/internal/fleet"
	"github.com/theworker02/ATDE/v2/internal/policy"
	"github.com/theworker02/ATDE/v2/internal/siem"
)

// CatchAPI mounts read-only catch ledger endpoints on the ops mux.
type CatchAPI struct {
	Ledger *catch.Ledger
	Token  string // empty = open (lab); set ATDE_OPS_TOKEN in production
	Policy *policy.Engine
	Fleet  *fleet.Store
}

func (a *CatchAPI) authorize(r *http.Request) bool {
	if a == nil || a.Token == "" {
		return true
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") && strings.TrimPrefix(h, "Bearer ") == a.Token {
		return true
	}
	if r.URL.Query().Get("token") == a.Token {
		return true
	}
	if r.Header.Get("X-ATDE-Token") == a.Token {
		return true
	}
	return false
}

func (a *CatchAPI) Mount(mux *http.ServeMux) {
	if a == nil || a.Ledger == nil {
		return
	}
	mux.HandleFunc("/v1/caught", a.caught)
	mux.HandleFunc("/v1/dossiers", a.dossiers)
	mux.HandleFunc("/v1/dossier/", a.dossier)
	mux.HandleFunc("/v1/export/", a.exportMD)
	mux.HandleFunc("/v1/stix/", a.exportSTIX)
	mux.HandleFunc("/v1/ecs/", a.exportECS)
	mux.HandleFunc("/v1/cef/", a.exportCEF)
	mux.HandleFunc("/v1/misp/", a.exportMISP)
	mux.HandleFunc("/v1/campaigns", a.campaigns)
	mux.HandleFunc("/v1/policy", a.policySnap)
	mux.HandleFunc("/v1/summary", a.summary)
	mux.HandleFunc("/v1/openapi.json", a.openapi)
	mux.HandleFunc("/v1/capabilities", a.capabilities)
	mux.HandleFunc("/console", a.console)
	mux.HandleFunc("/console/", a.console)
	if a.Fleet != nil {
		mux.HandleFunc("/v1/fleet/bans", func(w http.ResponseWriter, r *http.Request) {
			if !a.authorize(r) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			a.Fleet.Handler()(w, r)
		})
	}
}

func (a *CatchAPI) summary(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	st, err := a.Ledger.BuildStats(queryInt(r, "limit", 40))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, st)
}

func (a *CatchAPI) caught(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	limit := queryInt(r, "limit", 50)
	ip := r.URL.Query().Get("ip")
	var recs []catch.Record
	var err error
	if ip != "" {
		recs, err = a.Ledger.ListByIP(ip, limit)
	} else {
		recs, err = a.Ledger.ListRecent(limit)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"count": len(recs), "records": recs})
}

func (a *CatchAPI) dossiers(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	limit := queryInt(r, "limit", 100)
	list, err := a.Ledger.ListDossiers(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"count": len(list), "dossiers": list})
}

func (a *CatchAPI) dossier(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ip := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/dossier/"), "/")
	if ip == "" {
		http.Error(w, "missing ip", http.StatusBadRequest)
		return
	}
	d, err := a.Ledger.GetDossier(ip)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, d)
}

func (a *CatchAPI) exportMD(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ip := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/export/"), "/")
	md, err := a.Ledger.ExportMarkdown(ip)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "atde-"+ip+".md"))
	_, _ = w.Write([]byte(md))
}

func (a *CatchAPI) exportSTIX(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ip := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/stix/"), "/")
	raw, err := a.Ledger.ExportSTIX(ip)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/stix+json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "atde-"+ip+".stix.json"))
	_, _ = w.Write([]byte(raw))
}

func (a *CatchAPI) capabilities(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	writeJSON(w, map[string]any{
		"product": "ATDE",
		"line":    "2.0",
		"baits": []string{
			"http-atlas", "ssh", "redis", "telnet", "mysql", "ftp",
			"smtp", "elasticsearch", "mongodb", "deception",
		},
		"disruption": []string{
			"graduated_policy", "tarpit", "local_first_ban", "cloud_immunize",
			"fleet_ban_sync", "abuse_pack", "stix", "ecs", "cef", "misp",
		},
		"catch_api": []string{
			"GET /v1/summary", "GET /v1/caught", "GET /v1/dossiers", "GET /v1/dossier/{ip}",
			"GET /v1/export/{ip}", "GET /v1/stix/{ip}", "GET /v1/ecs/{ip}", "GET /v1/cef/{ip}",
			"GET /v1/misp/{ip}", "GET /v1/campaigns", "GET /v1/policy", "GET /v1/fleet/bans",
			"GET /v1/openapi.json", "GET /v1/capabilities", "GET /console",
		},
		"cli": []string{"caught", "dossier", "export", "abuse", "stix", "seed-demo", "watch", "doctor", "status", "campaigns"},
		"notify": []string{"webhook", "smtp+openpgp"},
		"legal":  "defensive owned-infrastructure only — no hack-back",
	})
}

func (a *CatchAPI) campaigns(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	recs, err := a.Ledger.ListRecent(5_000)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	camps := campaign.Correlate(recs, 24*time.Hour)
	writeJSON(w, map[string]any{"count": len(camps), "campaigns": camps})
}

func (a *CatchAPI) policySnap(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if a.Policy == nil {
		writeJSON(w, map[string]any{"enabled": false})
		return
	}
	writeJSON(w, map[string]any{"enabled": true, "decisions": a.Policy.Snapshot()})
}

func (a *CatchAPI) exportECS(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ip := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/ecs/"), "/")
	recs, err := a.Ledger.ListByIP(ip, 100)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	raw, err := siem.ToECSJSONL(recs)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	_, _ = w.Write([]byte(raw))
}

func (a *CatchAPI) exportCEF(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ip := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/cef/"), "/")
	recs, err := a.Ledger.ListByIP(ip, 100)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for _, rec := range recs {
		_, _ = fmt.Fprintln(w, siem.ToCEF(rec))
	}
}

func (a *CatchAPI) exportMISP(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ip := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/misp/"), "/")
	d, err := a.Ledger.GetDossier(ip)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "not found", 404)
			return
		}
		http.Error(w, err.Error(), 500)
		return
	}
	recs, _ := a.Ledger.ListByIP(ip, 50)
	writeJSON(w, siem.ToMISP(d, recs))
}

func (a *CatchAPI) openapi(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(openapiCatchJSON))
}

const openapiCatchJSON = `{
  "openapi": "3.0.3",
  "info": {
    "title": "ATDE Catch API",
    "version": "2.0.0",
    "description": "Threat disruption catch API — dossiers, campaigns, SIEM exports, fleet bans (owned nodes only)."
  },
  "paths": {
    "/v1/summary": {"get": {"summary": "Catch dashboard stats"}},
    "/v1/caught": {"get": {"summary": "List recent records"}},
    "/v1/dossiers": {"get": {"summary": "List dossiers"}},
    "/v1/dossier/{ip}": {"get": {"summary": "Get one dossier"}},
    "/v1/export/{ip}": {"get": {"summary": "Abuse Markdown"}},
    "/v1/stix/{ip}": {"get": {"summary": "STIX 2.1"}},
    "/v1/ecs/{ip}": {"get": {"summary": "ECS JSONL"}},
    "/v1/cef/{ip}": {"get": {"summary": "CEF lines"}},
    "/v1/misp/{ip}": {"get": {"summary": "MISP Event"}},
    "/v1/campaigns": {"get": {"summary": "Correlated campaigns"}},
    "/v1/policy": {"get": {"summary": "Policy decisions"}},
    "/v1/fleet/bans": {"get": {"summary": "Owned-node ban sync"}},
    "/v1/capabilities": {"get": {"summary": "Capability map"}},
    "/v1/openapi.json": {"get": {"summary": "This document"}}
  }
}`

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func (a *CatchAPI) console(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(r) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`<!doctype html><meta charset=utf-8><title>ATDE</title>
<style>body{font-family:"Segoe UI",ui-sans-serif,system-ui;background:#071016;color:#e7ecf1;display:grid;place-items:center;min-height:100vh;margin:0}
form{background:#121a22;padding:2rem;border-radius:14px;width:min(380px,92vw);border:1px solid #243041}
input,button{width:100%;padding:.75rem;margin:.45rem 0;border-radius:10px;border:1px solid #2c3a4a;background:#0b1218;color:#e7ecf1}
button{background:#2dd4bf;color:#042f2e;font-weight:700;cursor:pointer;border:0}</style>
<form method=GET action=/console><h1 style="margin:0 0 .5rem">ATDE Console</h1><p style="color:#8b9bb0">Enter ops token</p>
<input name=token type=password placeholder=ATDE_OPS_TOKEN required autofocus>
<button type=submit>Open live catch feed</button></form>`))
		return
	}
	token := a.Token
	if q := r.URL.Query().Get("token"); q != "" {
		token = q
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(consoleHTML(token)))
}

func consoleHTML(token string) string {
	tokJS, _ := json.Marshal(token)
	return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ATDE Live Catch Console</title>
<style>
:root{--bg:#070d12;--panel:#101820;--line:#1e2a36;--text:#eaf0f6;--muted:#8fa0b3;--accent:#2dd4bf;--hot:#f59e0b;--crit:#f43f5e;--ok:#34d399}
*{box-sizing:border-box}body{margin:0;font-family:"Segoe UI",ui-sans-serif,system-ui,sans-serif;background:
radial-gradient(900px 420px at 0% -10%,#0f3d4a55,transparent 60%),
radial-gradient(700px 380px at 100% 0%,#3b1d3555,transparent 55%),var(--bg);color:var(--text)}
header{display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap;padding:1rem 1.25rem;border-bottom:1px solid var(--line);position:sticky;top:0;background:#070d12e6;backdrop-filter:blur(10px);z-index:5}
h1{font-size:1.15rem;margin:0;letter-spacing:.06em}h1 span{color:var(--accent)}
.meta{color:var(--muted);font-size:.85rem}
.live{display:inline-flex;align-items:center;gap:.4rem}.dot{width:.55rem;height:.55rem;border-radius:50%;background:var(--ok);box-shadow:0 0 0 0 #34d39988;animation:pulse 1.6s infinite}
@keyframes pulse{70%{box-shadow:0 0 0 10px transparent}100%{box-shadow:0 0 0 0 transparent}}
main{display:grid;grid-template-columns:1.15fr .85fr;gap:1rem;padding:1rem;max-width:1280px;margin:0 auto}
@media(max-width:980px){main{grid-template-columns:1fr}}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:.75rem;padding:0 1rem;max-width:1280px;margin:.75rem auto 0}
@media(max-width:800px){.stats{grid-template-columns:repeat(2,1fr)}}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:.9rem 1rem}
.stat .k{color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.08em}.stat .v{font-size:1.55rem;font-weight:700;margin-top:.2rem;font-variant-numeric:tabular-nums}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:1rem;min-height:320px}
h2{margin:0 0 .75rem;font-size:.8rem;color:var(--muted);font-weight:650;text-transform:uppercase;letter-spacing:.1em}
table{width:100%;border-collapse:collapse;font-size:.88rem}
th,td{text-align:left;padding:.5rem .35rem;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:500}tr{cursor:pointer}tr:hover{background:#16202a}
.badge{display:inline-block;padding:.12rem .45rem;border-radius:999px;background:#0f766e33;color:var(--accent);font-size:.72rem;margin-right:.25rem}
.sev{font-weight:700;font-variant-numeric:tabular-nums}.sev.hi{color:var(--crit)}.sev.mid{color:var(--hot)}.sev.lo{color:var(--accent)}
.ip{font-family:ui-monospace,Consolas,monospace}
pre{white-space:pre-wrap;word-break:break-word;background:#070d12;border:1px solid var(--line);border-radius:10px;padding:.75rem;max-height:460px;overflow:auto;font-size:.78rem}
.actions{display:flex;gap:.5rem;flex-wrap:wrap;margin:.5rem 0}
button,.btn{background:var(--accent);color:#042f2e;border:0;border-radius:9px;padding:.45rem .75rem;font-weight:700;cursor:pointer;text-decoration:none;font-size:.85rem}
button.secondary,.btn.secondary{background:transparent;color:var(--text);border:1px solid var(--line)}
.empty{color:var(--muted);padding:1.25rem 0;line-height:1.5}
.feed{max-height:520px;overflow:auto}
.feed-item{padding:.55rem 0;border-bottom:1px solid var(--line);font-size:.86rem}
.feed-item .t{color:var(--muted);font-size:.75rem}
.chips{display:flex;flex-wrap:wrap;gap:.35rem;margin-top:.75rem}
.chip{background:#0b1218;border:1px solid var(--line);border-radius:999px;padding:.2rem .55rem;font-size:.75rem;color:var(--muted)}
footer{max-width:1280px;margin:0 auto 1.5rem;padding:0 1rem;color:var(--muted);font-size:.8rem}
</style></head><body>
<header>
  <div>
    <h1><span>ATDE</span> Threat Disruption Console <small style="color:var(--muted);font-weight:500">2.0</small></h1>
    <div class="meta live"><span class="dot"></span> 10 baits · policy engine · campaigns · SIEM export</div>
  </div>
  <div class="meta" id="status">loading…</div>
</header>
<section class="stats" id="stats"></section>
<main>
  <section class="card">
    <h2>Hot dossiers</h2>
    <div class="actions">
      <button type="button" onclick="refresh()">Refresh</button>
      <button type="button" class="secondary" onclick="showFeed()">Live feed</button>
    </div>
    <div id="list" class="empty">Waiting for the first public hit… Expose ports 8080 / 2222 / 6379 / 2323 / 3306 / 2121 / 8443.</div>
  </section>
  <section class="card">
    <h2>Detail</h2>
    <div id="detail" class="empty">Select an IP — or open Live feed</div>
  </section>
</main>
<footer>ATDE 2.0 · Defensive disruption only · ATDE_OPS_TOKEN · /v1/campaigns · /v1/fleet/bans · docs/CATCH.md</footer>
<script>
const TOKEN = ` + string(tokJS) + `;
function authURL(path){
  if(!TOKEN) return path;
  return path + (path.includes('?') ? '&' : '?') + 'token=' + encodeURIComponent(TOKEN);
}
async function jget(path){
  const headers = TOKEN ? {'X-ATDE-Token': TOKEN} : {};
  const r = await fetch(authURL(path), {headers});
  if(!r.ok) throw new Error(path + ' ' + r.status);
  return r.json();
}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function sevClass(n){n=+n||0; if(n>=70) return 'hi'; if(n>=40) return 'mid'; return 'lo';}
function fmtTime(t){ if(!t) return '—'; return String(t).replace('T',' ').slice(0,19)+'Z'; }
async function refresh(){
  try{
    const st = await jget('/v1/status');
    const sum = await jget('/v1/summary?limit=50');
    document.getElementById('status').textContent = 'v'+st.version+' · '+st.mode+' · up '+st.uptime_sec+'s';
    document.getElementById('stats').innerHTML =
      stat('Hits', sum.hits||0)+stat('Unique IPs', sum.unique_ips||0)+stat('Blocked', sum.blocked_ips||0)+stat('Max severity', sum.max_severity||0);
    const chips = [];
    for(const t of (sum.top_tools||[])) chips.push('<span class="chip">'+esc(t.name)+' · '+t.count+'</span>');
    for(const t of (sum.top_tags||[]).slice(0,6)) chips.push('<span class="chip">#'+esc(t.name)+' '+t.count+'</span>');
    const box = document.getElementById('list');
    const dossiers = sum.hot_dossiers || [];
    if(!dossiers.length){
      box.innerHTML = '<div class="empty">No attackers yet.<br>From the internet: <code>curl http://YOUR_IP:8080/login</code><br>Then this panel fills automatically.</div><div class="chips">'+chips.join('')+'</div>';
      return;
    }
    let html = '<table><thead><tr><th>IP</th><th>Sev</th><th>Hits</th><th>Last</th><th>What</th></tr></thead><tbody>';
    for(const d of dossiers){
      html += '<tr onclick="showIP(\''+esc(d.ip)+'\')"><td class="ip">'+esc(d.ip)+(d.blocked?' <span class="badge">blocked</span>':'')+'</td>'+
        '<td class="sev '+sevClass(d.max_severity)+'">'+(d.max_severity||0)+'</td>'+
        '<td><span class="badge">'+d.hit_count+'</span></td>'+
        '<td>'+esc(fmtTime(d.last_seen))+'</td>'+
        '<td>'+esc(d.last_summary|| (d.services||[]).join(', '))+'</td></tr>';
    }
    html += '</tbody></table><div class="chips">'+chips.join('')+'</div>';
    box.innerHTML = html;
    window.__feed = sum.recent||[];
  }catch(e){ document.getElementById('status').textContent = String(e); }
}
function stat(k,v){ return '<div class="stat"><div class="k">'+k+'</div><div class="v">'+v+'</div></div>'; }
async function showIP(ip){
  const d = await jget('/v1/dossier/' + encodeURIComponent(ip));
  const events = await jget('/v1/caught?ip='+encodeURIComponent(ip)+'&limit=30');
  const exportURL = authURL('/v1/export/' + encodeURIComponent(ip));
  const stixURL = authURL('/v1/stix/' + encodeURIComponent(ip));
  let feed = '';
  for(const r of (events.records||[]).reverse()){
    feed += '<div class="feed-item"><div class="t">'+esc(fmtTime(r.caught_at))+' · sev <span class="sev '+sevClass(r.severity)+'">'+(r.severity||0)+'</span> · '+esc(r.tool||'')+'</div>'+
      '<div>'+esc(r.summary||r.reason)+' <span class="badge">'+esc(r.service||'')+'</span> '+esc(r.path||'')+'</div></div>';
  }
  document.getElementById('detail').innerHTML =
    '<div class="actions"><a class="btn" href="'+exportURL+'">Export Markdown</a><a class="btn secondary" href="'+stixURL+'">Export STIX 2.1</a></div>'+
    '<div class="feed">'+feed+'</div>'+
    '<pre>'+esc(JSON.stringify(d,null,2))+'</pre>';
}
function showFeed(){
  const items = window.__feed||[];
  if(!items.length){ document.getElementById('detail').innerHTML = '<div class="empty">No events yet.</div>'; return; }
  let html = '<div class="feed">';
  for(const r of items){
    html += '<div class="feed-item" onclick="showIP(\''+esc(r.ip)+'\')"><div class="t">'+esc(fmtTime(r.caught_at))+' · <span class="ip">'+esc(r.ip)+'</span> · sev <span class="sev '+sevClass(r.severity)+'">'+(r.severity||0)+'</span></div>'+
      '<div>'+esc(r.summary||r.reason)+' · '+esc(r.method||'')+' '+esc(r.path||'')+'</div></div>';
  }
  html += '</div>';
  document.getElementById('detail').innerHTML = html;
}
refresh();
setInterval(refresh, 8000);
</script>
</body></html>`
}
