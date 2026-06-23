package domain

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	TrustDomain = "containgo.local"

	WorkloadNameAPIGateway   = "api-gateway"
	WorkloadNameProtectedAPI = "protected-api"
	WorkloadNameControlPlane = "control-plane"
	WorkloadNameOrderClient  = "order-client"
	WorkloadNameReportClient = "report-client"
	WorkloadNameDemoctl      = "democtl"
	WorkloadNameDashboard    = "dashboard"

	SPIFFEIDAPIGateway = "spiffe://containgo.local/ns/containgo/sa/api-gateway"

	SPIFFEIDProtectedAPI = "spiffe://containgo.local/ns/containgo/sa/protected-api"

	SPIFFEIDControlPlane = "spiffe://containgo.local/ns/containgo/sa/control-plane"

	SPIFFEIDOrderClient = "spiffe://containgo.local/ns/containgo/sa/order-client"

	SPIFFEIDReportClient = "spiffe://containgo.local/ns/containgo/sa/report-client"

	SPIFFEIDDemoctl = "spiffe://containgo.local/ns/containgo/sa/democtl"

	SPIFFEIDDashboard = "spiffe://containgo.local/ns/containgo/sa/dashboard"
)

// WorkloadStatus represents the current enforcement state of a workload.
type WorkloadStatus string

const (
	WorkloadStatusActive      WorkloadStatus = "active"
	WorkloadStatusQuarantined WorkloadStatus = "quarantined"
)

// Workload represents a registered ContainGo workload and its current
// security state.
type Workload struct {
	ID             int64          `json:"id"`
	Name           string         `json:"name"`
	SPIFFEID       string         `json:"spiffe_id"`
	Status         WorkloadStatus `json:"status"`
	RiskScore      int            `json:"risk_score"`
	DeniedRequests int            `json:"denied_requests"`
	LastSeenAt     *time.Time     `json:"last_seen_at,omitempty"`
	QuarantinedAt  *time.Time     `json:"quarantined_at,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

// Validate checks whether a workload contains a known SPIFFE identity and
// internally consistent state.
func (w Workload) Validate() error {
	if strings.TrimSpace(w.Name) == "" {
		return errors.New("workload name must not be empty")
	}

	if err := validateSPIFFEID(w.SPIFFEID); err != nil {
		return fmt.Errorf("SPIFFE ID: %w", err)
	}

	knownName, known := KnownWorkloadName(w.SPIFFEID)
	if !known {
		return fmt.Errorf(
			"unknown workload SPIFFE ID %q",
			w.SPIFFEID,
		)
	}

	if knownName != strings.TrimSpace(w.Name) {
		return fmt.Errorf(
			"workload name %q does not match SPIFFE identity name %q",
			w.Name,
			knownName,
		)
	}

	switch w.Status {
	case WorkloadStatusActive:
		if w.QuarantinedAt != nil {
			return errors.New(
				"active workload must not have a quarantine timestamp",
			)
		}

	case WorkloadStatusQuarantined:
		if w.QuarantinedAt == nil || w.QuarantinedAt.IsZero() {
			return errors.New(
				"quarantined workload must have a quarantine timestamp",
			)
		}

	default:
		return fmt.Errorf(
			"unsupported workload status %q",
			w.Status,
		)
	}

	if w.RiskScore < 0 {
		return errors.New("risk score must not be negative")
	}

	if w.DeniedRequests < 0 {
		return errors.New(
			"denied-request count must not be negative",
		)
	}

	if w.CreatedAt.IsZero() {
		return errors.New(
			"created-at timestamp must not be zero",
		)
	}

	if w.UpdatedAt.IsZero() {
		return errors.New(
			"updated-at timestamp must not be zero",
		)
	}

	return nil
}

// IsQuarantined reports whether OPA should deny every protected request
// from this workload.
func (w Workload) IsQuarantined() bool {
	return w.Status == WorkloadStatusQuarantined
}

// KnownWorkloadName returns the application name associated with a known
// SPIFFE identity.
func KnownWorkloadName(spiffeID string) (string, bool) {
	name, found := knownWorkloadNames[strings.TrimSpace(spiffeID)]

	return name, found
}

// IsKnownWorkloadID reports whether the SPIFFE identity belongs to a
// registered ContainGo component.
func IsKnownWorkloadID(spiffeID string) bool {
	_, found := KnownWorkloadName(spiffeID)

	return found
}

// KnownWorkloadIDs returns a sorted copy of all registered identities.
func KnownWorkloadIDs() []string {
	ids := make([]string, 0, len(knownWorkloadNames))

	for id := range knownWorkloadNames {
		ids = append(ids, id)
	}

	sort.Strings(ids)

	return ids
}

var knownWorkloadNames = map[string]string{
	SPIFFEIDAPIGateway:   WorkloadNameAPIGateway,
	SPIFFEIDProtectedAPI: WorkloadNameProtectedAPI,
	SPIFFEIDControlPlane: WorkloadNameControlPlane,
	SPIFFEIDOrderClient:  WorkloadNameOrderClient,
	SPIFFEIDReportClient: WorkloadNameReportClient,
	SPIFFEIDDemoctl:      WorkloadNameDemoctl,
	SPIFFEIDDashboard:    WorkloadNameDashboard,
}
