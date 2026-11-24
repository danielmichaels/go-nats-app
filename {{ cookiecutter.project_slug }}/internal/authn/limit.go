package authn

import (
	"sync"
	"time"
)

const (
	maxFailures = 5
	failWindow  = 5 * time.Minute
)

// limiter counts failed logins per key in memory. Each replica counts on its
// own, so the real limit is per replica.
type limiter struct {
	mu        sync.Mutex
	failures  map[string][]time.Time
	lastSweep time.Time
}

func newLimiter() *limiter { return &limiter{failures: map[string][]time.Time{}} }

func (l *limiter) recent(key string, now time.Time) []time.Time {
	keep := l.failures[key][:0]
	for _, t := range l.failures[key] {
		if now.Sub(t) < failWindow {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(l.failures, key)
	} else {
		l.failures[key] = keep
	}
	return keep
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	limit := maxFailures
	if len(key) > 3 && key[:3] == "ip:" {
		limit = 4 * maxFailures
	}
	return len(l.recent(key, time.Now())) < limit
}

func (l *limiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.failures[key] = append(l.failures[key], now)
	if now.Sub(l.lastSweep) > failWindow {
		l.lastSweep = now
		for k := range l.failures {
			l.recent(k, now)
		}
	}
}

func (l *limiter) clear(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
}
