package tenableio

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/captainpacket/tenableio-sc-proxy/internal/auth"
)

func TestFetchHostAggregatesPagination(t *testing.T) {
	t.Helper()

	var offsets []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		offset := r.URL.Query().Get("offset")
		limit := r.URL.Query().Get("limit")
		offsets = append(offsets, offset+":"+limit)

		switch offset {
		case "0":
			writeJSON(t, w, map[string]any{
				"assets": []map[string]any{
					{"ipv4": "10.0.0.1", "medium_count": 1, "high_count": 0, "critical_count": 0},
					{"ipv4": "10.0.0.2", "medium_count": 0, "high_count": 2, "critical_count": 0},
				},
				"pagination": map[string]any{"total": 3, "has_next": true},
			})
		case "2":
			writeJSON(t, w, map[string]any{
				"assets": []map[string]any{
					{"ipv4": "10.0.0.3", "medium_count": 0, "high_count": 0, "critical_count": 3},
				},
				"pagination": map[string]any{"total": 3, "has_next": false},
			})
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	client := NewWorkbenchClient(
		logger,
		srv.URL,
		"/workbenches/assets/vulnerabilities",
		2*time.Second,
		false,
		2,
		10*time.Millisecond,
		25*time.Millisecond,
		false,
		0,
	)

	rows, err := client.FetchHostAggregates(context.Background(), auth.Credentials{
		AccessKey: "ak",
		SecretKey: "sk",
	})
	if err != nil {
		t.Fatalf("FetchHostAggregates error: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(rows))
	}
	if !slices.Equal(offsets, []string{"0:5000", "2:5000"}) {
		t.Fatalf("unexpected offset/limit sequence: %v", offsets)
	}
}

func TestFetchHostAggregatesRetry429ThenSuccess(t *testing.T) {
	t.Helper()

	attempt := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt++
		if attempt == 1 {
			w.Header().Set("Retry-After", "0")
			http.Error(w, `{"error":"rate limited"}`, http.StatusTooManyRequests)
			return
		}
		writeJSON(t, w, map[string]any{
			"assets":     []map[string]any{{"ipv4": "10.0.0.10", "medium_count": 1, "high_count": 1, "critical_count": 1}},
			"pagination": map[string]any{"total": 1, "has_next": false},
		})
	}))
	defer srv.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	client := NewWorkbenchClient(
		logger,
		srv.URL,
		"/workbenches/assets/vulnerabilities",
		2*time.Second,
		false,
		3,
		1*time.Millisecond,
		10*time.Millisecond,
		false,
		128,
	)

	rows, err := client.FetchHostAggregates(context.Background(), auth.Credentials{
		AccessKey: "ak",
		SecretKey: "sk",
	})
	if err != nil {
		t.Fatalf("FetchHostAggregates error: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if attempt != 2 {
		t.Fatalf("expected exactly 2 attempts, got %d", attempt)
	}
}

func TestParseHostPageSeverityFallbacks(t *testing.T) {
	t.Helper()

	body := []byte(`{
		"results": [
			{
				"ip": "10.0.0.20",
				"risk": {"score": "77"},
				"severities": {"2": 4, "high": "5", "critical": 6}
			}
		],
		"pagination": {"total": 1, "has_next": false}
	}`)

	page, err := parseHostPage(body)
	if err != nil {
		t.Fatalf("parseHostPage error: %v", err)
	}
	if page.SourceField != "results" {
		t.Fatalf("expected source field results, got %q", page.SourceField)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(page.Rows))
	}
	row := page.Rows[0]
	if row.Medium != 4 || row.High != 5 || row.Critical != 6 {
		t.Fatalf("unexpected severity counts: medium=%d high=%d critical=%d", row.Medium, row.High, row.Critical)
	}
	if row.Score == nil || *row.Score != 77 {
		t.Fatalf("unexpected score: %#v", row.Score)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("encode json: %v", err)
	}
}
