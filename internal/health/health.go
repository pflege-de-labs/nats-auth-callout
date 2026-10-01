// Package health serves liveness and readiness probes.
package health

import (
	"context"
	"net/http"
	"time"
)

// Check reports an error when a dependency is not usable.
type Check func(context.Context) error

// Liveness answers 200 as long as the HTTP server goroutine runs.
func Liveness() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
}

// Readiness answers 503 with the failing reason while any check fails.
func Readiness(timeout time.Duration, checks map[string]Check) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		for name, c := range checks {
			if err := c(ctx); err != nil {
				http.Error(w, name+": "+err.Error(), http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
}
