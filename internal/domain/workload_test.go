package domain

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestWorkloadValidate(t *testing.T) {
	now := time.Date(
		2026,
		time.June,
		20,
		12,
		0,
		0,
		0,
		time.UTC,
	)
	quarantinedAt := now.Add(time.Minute)

	valid := Workload{
		Name:       WorkloadNameReportClient,
		SPIFFEID:   SPIFFEIDReportClient,
		Status:     WorkloadStatusActive,
		RiskScore:  25,
		CreatedAt:  now,
		UpdatedAt:  now,
		LastSeenAt: &now,
	}

	tests := []struct {
		name    string
		mutate  func(*Workload)
		wantErr string
	}{
		{
			name:   "accepts active workload",
			mutate: func(_ *Workload) {},
		},
		{
			name: "accepts quarantined workload",
			mutate: func(workload *Workload) {
				workload.Status = WorkloadStatusQuarantined
				workload.QuarantinedAt = &quarantinedAt
			},
		},
		{
			name: "rejects empty name",
			mutate: func(workload *Workload) {
				workload.Name = " "
			},
			wantErr: "workload name must not be empty",
		},
		{
			name: "rejects malformed SPIFFE identity",
			mutate: func(workload *Workload) {
				workload.SPIFFEID =
					"https://containgo.local/report-client"
			},
			wantErr: "scheme must be spiffe",
		},
		{
			name: "rejects unknown SPIFFE identity",
			mutate: func(workload *Workload) {
				workload.SPIFFEID =
					"spiffe://containgo.local/ns/containgo/sa/unknown"
			},
			wantErr: "unknown workload SPIFFE ID",
		},
		{
			name: "rejects mismatched name and identity",
			mutate: func(workload *Workload) {
				workload.Name = WorkloadNameOrderClient
			},
			wantErr: "does not match SPIFFE identity name",
		},
		{
			name: "rejects active workload with quarantine timestamp",
			mutate: func(workload *Workload) {
				workload.QuarantinedAt = &quarantinedAt
			},
			wantErr: "active workload must not have a quarantine timestamp",
		},
		{
			name: "rejects quarantined workload without timestamp",
			mutate: func(workload *Workload) {
				workload.Status = WorkloadStatusQuarantined
			},
			wantErr: "quarantined workload must have a quarantine timestamp",
		},
		{
			name: "rejects unsupported status",
			mutate: func(workload *Workload) {
				workload.Status = WorkloadStatus("disabled")
			},
			wantErr: "unsupported workload status",
		},
		{
			name: "rejects negative risk score",
			mutate: func(workload *Workload) {
				workload.RiskScore = -1
			},
			wantErr: "risk score must not be negative",
		},
		{
			name: "rejects negative denied-request count",
			mutate: func(workload *Workload) {
				workload.DeniedRequests = -1
			},
			wantErr: "denied-request count must not be negative",
		},
		{
			name: "rejects zero created timestamp",
			mutate: func(workload *Workload) {
				workload.CreatedAt = time.Time{}
			},
			wantErr: "created-at timestamp must not be zero",
		},
		{
			name: "rejects zero updated timestamp",
			mutate: func(workload *Workload) {
				workload.UpdatedAt = time.Time{}
			},
			wantErr: "updated-at timestamp must not be zero",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workload := valid
			tt.mutate(&workload)

			err := workload.Validate()

			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf(
						"Validate() unexpected error: %v",
						err,
					)
				}

				return
			}

			if err == nil ||
				!strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf(
					"Validate() error = %v, want error containing %q",
					err,
					tt.wantErr,
				)
			}
		})
	}
}

func TestWorkloadIdentityHelpers(t *testing.T) {
	name, found := KnownWorkloadName(
		"  " + SPIFFEIDOrderClient + "  ",
	)
	if !found {
		t.Fatal(
			"KnownWorkloadName() found = false, want true",
		)
	}

	if name != WorkloadNameOrderClient {
		t.Fatalf(
			"KnownWorkloadName() = %q, want %q",
			name,
			WorkloadNameOrderClient,
		)
	}

	unknownID :=
		"spiffe://containgo.local/ns/containgo/sa/unknown"

	if IsKnownWorkloadID(unknownID) {
		t.Fatal(
			"IsKnownWorkloadID() = true for unknown identity",
		)
	}

	wantIDs := []string{
		SPIFFEIDAPIGateway,
		SPIFFEIDControlPlane,
		SPIFFEIDDemoctl,
		SPIFFEIDDashboard,
		SPIFFEIDOrderClient,
		SPIFFEIDProtectedAPI,
		SPIFFEIDReportClient,
	}
	slices.Sort(wantIDs)

	gotIDs := KnownWorkloadIDs()

	if !slices.Equal(gotIDs, wantIDs) {
		t.Fatalf(
			"KnownWorkloadIDs() = %v, want %v",
			gotIDs,
			wantIDs,
		)
	}

	// Ensure callers cannot modify the internal identity map
	// through the returned slice.
	gotIDs[0] = "modified"

	if KnownWorkloadIDs()[0] == "modified" {
		t.Fatal(
			"KnownWorkloadIDs() exposed mutable internal state",
		)
	}
}

func TestWorkloadIsQuarantined(t *testing.T) {
	active := Workload{
		Status: WorkloadStatusActive,
	}

	if active.IsQuarantined() {
		t.Fatal(
			"active workload reported as quarantined",
		)
	}

	quarantined := Workload{
		Status: WorkloadStatusQuarantined,
	}

	if !quarantined.IsQuarantined() {
		t.Fatal(
			"quarantined workload reported as active",
		)
	}
}
