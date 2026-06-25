package platform

import "time"

type IdentityInfo struct {
	Workload       string    `json:"workload,omitempty"`
	SPIFFEID       string    `json:"spiffe_id"`
	SerialNumber   string    `json:"serial_number"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
	Issuer         string    `json:"issuer"`
	Subject        string    `json:"subject"`
	DNSNames       []string  `json:"dns_names,omitempty"`
	CertificatePEM string    `json:"-"`
}

type TLSMetadata struct {
	Protocol       string    `json:"protocol"`
	TLSVersion     string    `json:"tls_version"`
	CipherSuite    string    `json:"cipher_suite"`
	SourceSPIFFEID string    `json:"source_spiffe_id"`
	PeerSPIFFEID   string    `json:"peer_spiffe_id"`
	SerialNumber   string    `json:"serial_number"`
	ValidFrom      time.Time `json:"valid_from"`
	ValidUntil     time.Time `json:"valid_until"`
}

type TraceHop struct {
	From       string      `json:"from"`
	To         string      `json:"to"`
	Stage      string      `json:"stage"`
	Status     string      `json:"status"`
	OccurredAt time.Time   `json:"occurred_at"`
	TLS        TLSMetadata `json:"tls"`
	Details    string      `json:"details,omitempty"`
}

type DecisionEvent struct {
	TraceID        string                 `json:"trace_id"`
	GatewayRequest string                 `json:"gateway_request_id"`
	Workload       string                 `json:"workload"`
	SPIFFEID       string                 `json:"spiffe_id"`
	Method         string                 `json:"method"`
	Path           string                 `json:"path"`
	Decision       string                 `json:"decision"`
	Reason         string                 `json:"reason"`
	StatusCode     int                    `json:"status_code"`
	OccurredAt     time.Time              `json:"occurred_at"`
	Hops           []TraceHop             `json:"hops"`
	RequestBody    string                 `json:"request_body,omitempty"`
	ResponseBody   string                 `json:"response_body,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

type WorkloadState struct {
	Name             string    `json:"name"`
	SPIFFEID         string    `json:"spiffe_id"`
	Role             string    `json:"role"`
	RiskScore        int       `json:"risk_score"`
	Status           string    `json:"status"`
	DeniedRequests   int       `json:"denied_requests"`
	AllowedRequests  int       `json:"allowed_requests"`
	LastSeen         time.Time `json:"last_seen,omitempty"`
	QuarantinedAt    time.Time `json:"quarantined_at,omitempty"`
	LastDecision     string    `json:"last_decision,omitempty"`
	LastDecisionPath string    `json:"last_decision_path,omitempty"`
}

type StoredEvent struct {
	Sequence        int64         `json:"sequence"`
	DecisionEvent   DecisionEvent `json:"decision_event"`
	RiskBefore      int           `json:"risk_before"`
	RiskDelta       int           `json:"risk_delta"`
	RiskAfter       int           `json:"risk_after"`
	Quarantined     bool          `json:"quarantined"`
	RiskReasons     []string      `json:"risk_reasons"`
	ControlPlaneHop *TraceHop     `json:"control_plane_hop,omitempty"`
}

type Incident struct {
	ID            string    `json:"id"`
	Workload      string    `json:"workload"`
	SPIFFEID      string    `json:"spiffe_id"`
	OpenedAt      time.Time `json:"opened_at"`
	ResolvedAt    time.Time `json:"resolved_at,omitempty"`
	Status        string    `json:"status"`
	ScoreAtOpen   int       `json:"score_at_open"`
	Threshold     int       `json:"threshold"`
	TriggerTrace  string    `json:"trigger_trace"`
	EvidenceCount int       `json:"evidence_count"`
	Resolution    string    `json:"resolution,omitempty"`
}

type Endpoint struct {
	Method      string   `json:"method"`
	Path        string   `json:"path"`
	Description string   `json:"description"`
	AllowedFor  []string `json:"allowed_for"`
	RiskLabel   string   `json:"risk_label,omitempty"`
}
