package catch

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Watch appends new events from events.jsonl to out until done is closed.
func (l *Ledger) Watch(done <-chan struct{}, out io.Writer) error {
	if l == nil {
		return fmt.Errorf("catch: nil ledger")
	}
	path := filepath.Join(l.Dir, "events.jsonl")
	var offset int64
	if st, err := os.Stat(path); err == nil {
		offset = st.Size()
	}
	enc := json.NewEncoder(out)
	for {
		select {
		case <-done:
			return nil
		default:
		}
		n, err := l.drainFrom(path, offset, enc)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		offset = n
		time.Sleep(500 * time.Millisecond)
	}
}

func (l *Ledger) drainFrom(path string, offset int64, enc *json.Encoder) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return offset, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return offset, err
	}
	size := st.Size()
	if size < offset {
		offset = 0 // rotated
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return offset, err
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			continue
		}
		if err := enc.Encode(r); err != nil {
			return offset, err
		}
	}
	return size, sc.Err()
}
