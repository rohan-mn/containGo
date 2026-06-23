package domain

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SecurityDecision is the gateway authorization result associated with an event.
type SecurityDecision string

const (
	DecisionAllowed SecurityDecision = "allowed"
	DecisionDenied  SecurityDecision = "denied"
)

// SecurityEvent records one authenticated workload request observed by the
// API Gateway.
//
// WorkloadID must come from the verified SPIFFE mTLS connection, never from
// an HTTP header.
type SecurityEvent struct {
	ID         int64            `json:"id"`
	RequestID  string           `json:"request_id"`
	WorkloadID string           `json:"workload_id"`
	Method     string           `json:"method"`
	Path       string           `json:"path"`
	Decision   SecurityDecision `json:"decision"`
	StatusCode int              `json:"status_code"`
	Reason     string           `json:"reason,omitempty"`
	OccurredAt time.Time        `json:"occurred_at"`
}

// Validate rejects malformed events before they enter the risk engine
// or database.
func (e SecurityEvent) Validate() error {
	if strings.TrimSpace(e.RequestID) == "" {
		return errors.New("request ID must not be empty")
	}

	if err := validateSPIFFEID(e.WorkloadID); err != nil {
		return fmt.Errorf("workload ID: %w", err)
	}

	if strings.TrimSpace(e.Method) == "" {
		return errors.New("HTTP method must not be empty")
	}

	if strings.ToUpper(e.Method) != e.Method {
		return errors.New("HTTP method must be uppercase")
	}

	if !strings.HasPrefix(e.Path, "/") {
		return errors.New("request path must start with /")
	}

	if e.Decision != DecisionAllowed &&
		e.Decision != DecisionDenied {
		return fmt.Errorf(
			"unsupported security decision %q",
			e.Decision,
		)
	}

	if e.StatusCode < 100 || e.StatusCode > 599 {
		return errors.New(
			"status code must be between 100 and 599",
		)
	}

	if e.Decision == DecisionDenied &&
		strings.TrimSpace(e.Reason) == "" {
		return errors.New(
			"denied event must include a reason",
		)
	}

	if e.OccurredAt.IsZero() {
		return errors.New(
			"occurred-at timestamp must not be zero",
		)
	}

	return nil
}

// IsDenied reports whether the gateway denied the request.
func (e SecurityEvent) IsDenied() bool {
	return e.Decision == DecisionDenied
}

// NormalizedMethod returns the canonical HTTP method used by event producers.
func NormalizedMethod(method string) string {
	return strings.ToUpper(strings.TrimSpace(method))
}

// DefaultStatusCode returns the expected HTTP status for a decision.
func DefaultStatusCode(decision SecurityDecision) int {
	if decision == DecisionAllowed {
		return http.StatusOK
	}

	return http.StatusForbidden
}

func validateSPIFFEID(value string) error {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return fmt.Errorf("parse SPIFFE ID: %w", err)
	}

	if parsed.Scheme != "spiffe" {
		return errors.New("scheme must be spiffe")
	}

	if parsed.Host == "" {
		return errors.New("trust domain must not be empty")
	}

	if parsed.Path == "" || parsed.Path == "/" {
		return errors.New("workload path must not be empty")
	}

	if parsed.User != nil ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" {
		return errors.New(
			"SPIFFE ID must not contain user info, query, or fragment",
		)
	}

	return nil
}
