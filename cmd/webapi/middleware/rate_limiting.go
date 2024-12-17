package middleware

import (
	"net/http"
	"sync"
	"time"
)

var clients = make(map[string]time.Time)
var mu sync.Mutex

func RateLimitingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.RemoteAddr
		mu.Lock()
		lastSeen, exists := clients[clientIP]
		if exists && time.Since(lastSeen) < time.Second {
			mu.Unlock()
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		clients[clientIP] = time.Now()
		mu.Unlock()

		next.ServeHTTP(w, r)
	})
}
