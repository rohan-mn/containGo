package dashboard

import (
	"testing"
	"time"

	"containgo.local/containgo/internal/domain"
	"containgo.local/containgo/internal/reportclient"
)

func TestDeriveDemoStage(t *testing.T) {
	tests := []struct {
		name      string
		workload  domain.Workload
		mode      reportclient.Snapshot
		incidents []domain.Incident
		want      string
	}{
		{
			name:     "normal",
			workload: domain.Workload{Status: domain.WorkloadStatusActive},
			mode:     reportclient.Snapshot{Mode: reportclient.ModeNormal},
			want:     "normal",
		},
		{
			name:     "attacking",
			workload: domain.Workload{Status: domain.WorkloadStatusActive},
			mode:     reportclient.Snapshot{Mode: reportclient.ModeAttack},
			want:     "attacking",
		},
		{
			name:     "quarantined wins over mode",
			workload: domain.Workload{Status: domain.WorkloadStatusQuarantined},
			mode:     reportclient.Snapshot{Mode: reportclient.ModeAttack},
			want:     "quarantined",
		},
		{
			name:     "recovered",
			workload: domain.Workload{Status: domain.WorkloadStatusActive},
			mode: reportclient.Snapshot{
				Mode:      reportclient.ModeNormal,
				UpdatedAt: time.Date(2026, time.June, 22, 12, 0, 0, 0, time.UTC),
			},
			incidents: func() []domain.Incident {
				releasedAt := time.Date(2026, time.June, 22, 12, 0, 1, 0, time.UTC)
				return []domain.Incident{{
					Status:     domain.IncidentStatusReleased,
					ReleasedAt: &releasedAt,
				}}
			}(),
			want: "recovered",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, _ := deriveDemoStage(test.workload, test.mode, test.incidents)
			if got != test.want {
				t.Fatalf("stage = %q, want %q", got, test.want)
			}
		})
	}
}
