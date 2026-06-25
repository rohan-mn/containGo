package controlservice

import (
	"path/filepath"
	"testing"
	"time"

	"containgo.local/containgo/internal/platform"
)

func TestRiskAndQuarantine(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "state.json"), 100)
	if err != nil {
		t.Fatal(err)
	}
	base := platform.DecisionEvent{TraceID: "trace-1", Workload: "report-client", SPIFFEID: "spiffe://containgo.local/ns/containgo/sa/report-client", Method: "GET", Path: "/api/payment-details", Decision: "deny", StatusCode: 403, OccurredAt: time.Now()}
	first, err := store.Process(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.RiskAfter != 65 { // deny 25 + sensitive path 40
		t.Fatalf("risk after sensitive request = %d, want 65", first.RiskAfter)
	}
	base.TraceID = "trace-2"
	base.Method = "PUT"
	base.Path = "/api/admin/config"
	second, err := store.Process(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Quarantined || second.RiskAfter != 125 {
		t.Fatalf("expected quarantine at 125, got risk=%d quarantined=%t", second.RiskAfter, second.Quarantined)
	}
}
