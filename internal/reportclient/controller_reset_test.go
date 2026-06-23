package reportclient

import (
	"errors"
	"testing"
	"time"
)

func TestControllerResetStatsPreservesMode(t *testing.T) {
	controller, err := NewController(ModeNormal)
	if err != nil {
		t.Fatalf("NewController() error = %v", err)
	}

	now := time.Date(2026, time.June, 22, 12, 0, 0, 0, time.UTC)
	controller.RecordResponse("/api/reports", 200, now)
	controller.RecordResponse("/api/admin/config", 403, now.Add(time.Second))
	controller.RecordError("/api/reports", errors.New("network failure"), now.Add(2*time.Second))

	if err = controller.SetMode(ModeAttack); err != nil {
		t.Fatalf("SetMode() error = %v", err)
	}

	snapshot := controller.ResetStats()
	if snapshot.Mode != ModeAttack {
		t.Fatalf("mode = %q, want %q", snapshot.Mode, ModeAttack)
	}
	if snapshot.TotalRequests != 0 || snapshot.Successful != 0 || snapshot.Forbidden != 0 || snapshot.Failures != 0 {
		t.Fatalf("counters were not reset: %+v", snapshot)
	}
	if snapshot.LastPath != "" || snapshot.LastStatus != 0 || snapshot.LastError != "" || snapshot.LastRequestAt != nil {
		t.Fatalf("last request state was not reset: %+v", snapshot)
	}
}
