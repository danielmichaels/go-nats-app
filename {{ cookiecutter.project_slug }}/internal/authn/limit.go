package authn

import (
	"sync"
	"time"
)

const (
	userLimit  = 5
	ipLimit    = 20
	oidcLimit  = 30
	failWindow = 5 * time.Minute
)

// limiter counts events per key in memory: failed logins, or OIDC starts.
// Each replica counts on its own, so the real limit is per replica.
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

func (l *limiter) allow(key string, limit int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
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
