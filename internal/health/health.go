package health

import (
	"encoding/json"
	"net/http"
)

func Handler(version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"version": version,
		})
	}
}

func ReadyHandler(version string, readyFn func() (bool, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ready, reason := readyFn()
		status := http.StatusOK
		state := "ready"
		if !ready {
			status = http.StatusServiceUnavailable
			state = "not_ready"
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  state,
			"version": version,
			"reason":  reason,
		})
	}
}
