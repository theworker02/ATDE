package notify

import "github.com/theworker02/ATDE/v2/internal/catch"

// Fanout invokes multiple OnRecord handlers independently.
func Fanout(handlers ...catch.OnRecord) catch.OnRecord {
	var active []catch.OnRecord
	for _, h := range handlers {
		if h != nil {
			active = append(active, h)
		}
	}
	return func(r catch.Record) {
		for _, h := range active {
			h(r)
		}
	}
}
