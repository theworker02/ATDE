package catch

import (
	"sort"
	"time"
)

// Stats is a rollup for the operator console.
type Stats struct {
	Hits         int            `json:"hits"`
	UniqueIPs    int            `json:"unique_ips"`
	BlockedIPs   int            `json:"blocked_ips"`
	MaxSeverity  int            `json:"max_severity"`
	LastHitAt    time.Time      `json:"last_hit_at,omitempty"`
	TopTools     []NameCount    `json:"top_tools,omitempty"`
	TopTags      []NameCount    `json:"top_tags,omitempty"`
	TopPaths     []NameCount    `json:"top_paths,omitempty"`
	Recent       []Record       `json:"recent,omitempty"`
	HotDossiers  []Dossier      `json:"hot_dossiers,omitempty"`
}

type NameCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// BuildStats computes dashboard stats from recent events + dossiers.
func (l *Ledger) BuildStats(recentLimit int) (Stats, error) {
	var st Stats
	if recentLimit <= 0 {
		recentLimit = 40
	}
	recs, err := l.ListRecent(2_000)
	if err != nil {
		return st, err
	}
	st.Hits = len(recs)
	seen := map[string]struct{}{}
	tools := map[string]int{}
	tags := map[string]int{}
	paths := map[string]int{}
	for _, r := range recs {
		seen[r.IP] = struct{}{}
		if r.Severity > st.MaxSeverity {
			st.MaxSeverity = r.Severity
		}
		if r.CaughtAt.After(st.LastHitAt) {
			st.LastHitAt = r.CaughtAt
		}
		if r.Tool != "" {
			tools[r.Tool]++
		}
		for _, t := range r.Tags {
			tags[t]++
		}
		if r.Path != "" {
			paths[r.Path]++
		}
	}
	st.UniqueIPs = len(seen)
	dossiers, _ := l.ListDossiers(500)
	for _, d := range dossiers {
		if d.Blocked {
			st.BlockedIPs++
		}
	}
	st.TopTools = topN(tools, 8)
	st.TopTags = topN(tags, 10)
	st.TopPaths = topN(paths, 10)
	if len(recs) > recentLimit {
		st.Recent = recs[len(recs)-recentLimit:]
	} else {
		st.Recent = recs
	}
	// reverse recent so newest first for UI
	for i, j := 0, len(st.Recent)-1; i < j; i, j = i+1, j-1 {
		st.Recent[i], st.Recent[j] = st.Recent[j], st.Recent[i]
	}
	sort.Slice(dossiers, func(i, j int) bool {
		if dossiers[i].MaxSeverity == dossiers[j].MaxSeverity {
			return dossiers[i].HitCount > dossiers[j].HitCount
		}
		return dossiers[i].MaxSeverity > dossiers[j].MaxSeverity
	})
	if len(dossiers) > 15 {
		dossiers = dossiers[:15]
	}
	st.HotDossiers = dossiers
	return st, nil
}

func topN(m map[string]int, n int) []NameCount {
	type kv struct {
		k string
		v int
	}
	var list []kv
	for k, v := range m {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].v > list[j].v })
	if len(list) > n {
		list = list[:n]
	}
	out := make([]NameCount, 0, len(list))
	for _, x := range list {
		out = append(out, NameCount{Name: x.k, Count: x.v})
	}
	return out
}
