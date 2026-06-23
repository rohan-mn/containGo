package domain

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSecurityEventValidate(t *testing.T) {
	occurredAt := time.Date(
		2026,
		time.June,
		20,
		12,
		30,
		0,
		0,
		time.UTC,
	)

	valid := SecurityEvent{
		RequestID:  "req-1001",
		WorkloadID: SPIFFEIDReportClient,
		Method:     http.MethodGet,
		Path:       "/api/reports",
		Decision:   DecisionAllowed,
		StatusCode: http.StatusOK,
		OccurredAt: occurredAt,
	}

	tests := []struct {
		name    string
		mutate  func(*SecurityEvent)
		wantErr string
	}{
		{
			name: "accepts allowed event",
			mutate: func(_ *SecurityEvent) {
			},
		},
		{
			name: "accepts denied event with reason",
			mutate: func(event *SecurityEvent) {
				event.Decision = DecisionDenied
				event.StatusCode = http.StatusForbidden
				event.Reason = "endpoint not permitted for workload"
			},
		},
		{
			name: "rejects empty request ID",
			mutate: func(event *SecurityEvent) {
				event.RequestID = " "
			},
			wantErr: "request ID must not be empty",
		},
		{
			name: "rejects non-SPIFFE workload ID",
			mutate: func(event *SecurityEvent) {
				event.WorkloadID =
					"https://containgo.local/report-client"
			},
			wantErr: "scheme must be spiffe",
		},
		{
			name: "rejects SPIFFE ID without workload path",
			mutate: func(event *SecurityEvent) {
				event.WorkloadID = "spiffe://containgo.local"
			},
			wantErr: "workload path must not be empty",
		},
		{
			name: "rejects SPIFFE ID with query string",
			mutate: func(event *SecurityEvent) {
				event.WorkloadID =
					SPIFFEIDReportClient + "?admin=true"
			},
			wantErr: "must not contain user info, query, or fragment",
		},
		{
			name: "rejects lowercase method",
			mutate: func(event *SecurityEvent) {
				event.Method = "get"
			},
			wantErr: "HTTP method must be uppercase",
		},
		{
			name: "rejects path without leading slash",
			mutate: func(event *SecurityEvent) {
				event.Path = "api/reports"
			},
			wantErr: "request path must start with /",
		},
		{
			name: "rejects unsupported decision",
			mutate: func(event *SecurityEvent) {
				event.Decision = SecurityDecision("unknown")
			},
			wantErr: "unsupported security decision",
		},
		{
			name: "rejects invalid status code",
			mutate: func(event *SecurityEvent) {
				event.StatusCode = 700
			},
			wantErr: "status code must be between 100 and 599",
		},
		{
			name: "rejects denied event without reason",
			mutate: func(event *SecurityEvent) {
				event.Decision = DecisionDenied
				event.StatusCode = http.StatusForbidden
				event.Reason = ""
			},
			wantErr: "denied event must include a reason",
		},
		{
			name: "rejects zero timestamp",
			mutate: func(event *SecurityEvent) {
				event.OccurredAt = time.Time{}
			},
			wantErr: "occurred-at timestamp must not be zero",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := valid
			tt.mutate(&event)

			err := event.Validate()

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

func TestSecurityEventHelpers(t *testing.T) {
	denied := SecurityEvent{
		Decision: DecisionDenied,
	}

	if !denied.IsDenied() {
		t.Fatal("IsDenied() = false, want true")
	}

	allowed := SecurityEvent{
		Decision: DecisionAllowed,
	}

	if allowed.IsDenied() {
		t.Fatal("IsDenied() = true, want false")
	}

	if got := NormalizedMethod(" get "); got != http.MethodGet {
		t.Fatalf(
			"NormalizedMethod() = %q, want %q",
			got,
			http.MethodGet,
		)
	}

	if got := DefaultStatusCode(DecisionAllowed); got != http.StatusOK {
		t.Fatalf(
			"DefaultStatusCode(allowed) = %d, want %d",
			got,
			http.StatusOK,
		)
	}

	if got := DefaultStatusCode(DecisionDenied); got != http.StatusForbidden {
		t.Fatalf(
			"DefaultStatusCode(denied) = %d, want %d",
			got,
			http.StatusForbidden,
		)
	}
}
