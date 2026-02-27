package transform

import (
	"testing"

	"github.com/captainpacket/tenableio-sc-proxy/internal/tenableio"
)

func TestToSumipRowsWithStatsDedupeByIP(t *testing.T) {
	t.Helper()

	scoreA := 50
	scoreB := 90
	in := []tenableio.HostAggregate{
		{
			IP:       "10.0.0.1",
			DNSName:  "host-a",
			Score:    &scoreA,
			Medium:   1,
			High:     2,
			Critical: 0,
		},
		{
			IP:         "10.0.0.1",
			MACAddress: "00:11:22:33:44:55",
			Score:      &scoreB,
			Medium:     3,
			High:       1,
			Critical:   4,
		},
	}

	rows, stats := ToSumipRowsWithStats(in, Options{DedupeByIP: true})
	if len(rows) != 1 {
		t.Fatalf("expected 1 deduped row, got %d", len(rows))
	}
	if rows[0].IP != "10.0.0.1" {
		t.Fatalf("unexpected ip: %q", rows[0].IP)
	}
	if rows[0].DNSName != "host-a" {
		t.Fatalf("expected dnsName to preserve first non-empty value, got %q", rows[0].DNSName)
	}
	if rows[0].MACAddress != "00:11:22:33:44:55" {
		t.Fatalf("expected macAddress to fill from duplicate row, got %q", rows[0].MACAddress)
	}
	if rows[0].Score != "90" || rows[0].SeverityMedium != "3" || rows[0].SeverityHigh != "2" || rows[0].SeverityCritical != "4" {
		t.Fatalf("unexpected merged row: %#v", rows[0])
	}
	if stats.DuplicatesMerged != 1 {
		t.Fatalf("expected 1 merged duplicate, got %d", stats.DuplicatesMerged)
	}
}

func TestToSumipRowsWithStatsNoDedupe(t *testing.T) {
	t.Helper()

	score := 10
	in := []tenableio.HostAggregate{
		{IP: "10.0.0.1", Score: &score, Medium: 1, High: 1, Critical: 1},
		{IP: "10.0.0.1", Score: &score, Medium: 1, High: 1, Critical: 1},
	}

	rows, stats := ToSumipRowsWithStats(in, Options{DedupeByIP: false})
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows without dedupe, got %d", len(rows))
	}
	if stats.DuplicatesMerged != 0 {
		t.Fatalf("expected 0 merged duplicates, got %d", stats.DuplicatesMerged)
	}
}

func TestToSumipRowsWithStatsDropsInvalidRows(t *testing.T) {
	t.Helper()

	score := 20
	in := []tenableio.HostAggregate{
		{IP: "not-an-ip", Score: &score, Medium: 1, High: 1, Critical: 1},
		{IP: "10.0.0.2", Score: &score, Medium: -1, High: 1, Critical: 1},
		{IP: "10.0.0.3", Score: &score, Medium: 1, High: 1, Critical: 1},
	}

	rows, stats := ToSumipRowsWithStats(in, Options{DedupeByIP: true})
	if len(rows) != 1 {
		t.Fatalf("expected 1 valid output row, got %d", len(rows))
	}
	if stats.DroppedInvalidIP != 1 {
		t.Fatalf("expected 1 invalid-ip drop, got %d", stats.DroppedInvalidIP)
	}
	if stats.DroppedNegativeSeverity != 1 {
		t.Fatalf("expected 1 negative-severity drop, got %d", stats.DroppedNegativeSeverity)
	}
}
