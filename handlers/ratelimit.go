package handlers

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// rateLimiter counts failures per key within a sliding window. It exists to
// make password guessing against the login form impractical. State is
// per-process, which is sufficient for a single-instance blog.
type rateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	limit    int
	window   time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		attempts: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

// blocked reports whether key has already exceeded the limit.
func (l *rateLimiter) blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recentLocked(key)) >= l.limit
}

// fail records a failed attempt for key.
func (l *rateLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.attempts[key] = append(l.recentLocked(key), time.Now())
}

// reset clears the history for key after a success.
func (l *rateLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, key)
}

// recentLocked prunes and returns attempts still inside the window. It also
// opportunistically drops other expired keys so the map cannot grow without
// bound. The caller must hold l.mu.
func (l *rateLimiter) recentLocked(key string) []time.Time {
	cutoff := time.Now().Add(-l.window)

	kept := l.attempts[key][:0]
	for _, at := range l.attempts[key] {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	if len(kept) == 0 {
		delete(l.attempts, key)
	} else {
		l.attempts[key] = kept
	}

	for otherKey, times := range l.attempts {
		if otherKey == key {
			continue
		}
		if len(times) == 0 || times[len(times)-1].Before(cutoff) {
			delete(l.attempts, otherKey)
		}
	}

	return kept
}

// clientIP extracts a rate-limiting key from the request. RemoteAddr is used
// directly: proxy headers are attacker-controlled unless a trusted proxy is
// known to set them, and none is configured here.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
