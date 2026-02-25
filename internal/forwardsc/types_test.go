package forwardsc

import "testing"

func TestDaysAgo(t *testing.T) {
	req := AnalysisRequest{Query: Query{Filters: []Filter{{FilterName: "lastSeen", Value: "2:3"}}}}
	days, err := req.DaysAgo()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if days != 2 {
		t.Fatalf("unexpected daysAgo: %d", days)
	}
}
