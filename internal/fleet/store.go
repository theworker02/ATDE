package fleet

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// BanEntry is a shared containment decision for owned catch-nodes only.
type BanEntry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	Severity  int       `json:"severity"`
	Tier      string    `json:"tier"`
	BannedAt  time.Time `json:"banned_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Node      string    `json:"node,omitempty"`
}

// Store is a file-backed ban list for multi-node sync (pull model).
type Store struct {
	Path string
	Node string
	mu   sync.Mutex
}

func NewStore(path, node string) *Store {
	if path == "" {
		path = "./data/fleet/bans.json"
	}
	if node == "" {
		node = "atde-node"
	}
	return &Store{Path: path, Node: node}
}

func (s *Store) Upsert(e BanEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, _ := s.load()
	if e.BannedAt.IsZero() {
		e.BannedAt = time.Now().UTC()
	}
	if e.ExpiresAt.IsZero() {
		e.ExpiresAt = e.BannedAt.Add(24 * time.Hour)
	}
	if e.Node == "" {
		e.Node = s.Node
	}
	found := false
	for i := range list {
		if list[i].IP == e.IP {
			list[i] = e
			found = true
			break
		}
	}
	if !found {
		list = append(list, e)
	}
	return s.save(list)
}

func (s *Store) Active() ([]BanEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.load()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	var out []BanEntry
	for _, e := range list {
		if e.ExpiresAt.IsZero() || e.ExpiresAt.After(now) {
			out = append(out, e)
		}
	}
	return out, nil
}

func (s *Store) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := s.Active()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"node":    s.Node,
			"count":   len(list),
			"bans":    list,
			"note":    "ATDE fleet ban sync — apply only on nodes you own",
			"fetched": time.Now().UTC(),
		})
	}
}

func (s *Store) load() ([]BanEntry, error) {
	raw, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var list []BanEntry
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func (s *Store) save(list []BanEntry) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o750); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.Path, raw, 0o600)
}
