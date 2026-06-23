package domain

import (
	"errors"
	"fmt"
	"strings"
)

const QuarantineThreshold = 70

// RiskRule identifies why risk points were assigned to a workload.
type RiskRule string

const (
	RiskRuleUnauthorizedEndpoint RiskRule = "unauthorized_endpoint"

	RiskRuleFiveDeniedRequests RiskRule = "five_denied_requests_60s"

	RiskRuleHighRequestRate RiskRule = "more_than_30_requests_60s"

	RiskRuleSensitiveEndpoint RiskRule = "sensitive_endpoint_attempt"

	RiskRuleAdministrative RiskRule = "administrative_endpoint_attempt"

	RiskRuleHighlySensitive RiskRule = "highly_sensitive_endpoint_attempt"
)

const (
	UnauthorizedEndpointPoints = 25
	FiveDeniedRequestsPoints   = 25
	HighRequestRatePoints      = 20
	SensitiveEndpointPoints    = 30
	AdministrativePoints       = 35
	HighlySensitivePoints      = 40
)

// RiskContribution records one verified reason for increasing a workload's
// risk score.
type RiskContribution struct {
	Rule   RiskRule `json:"rule"`
	Points int      `json:"points"`
	Reason string   `json:"reason"`
}

// NewRiskContribution creates a contribution using the server-controlled
// score associated with the specified rule.
//
// Callers cannot choose an arbitrary point value.
func NewRiskContribution(
	rule RiskRule,
	reason string,
) (RiskContribution, error) {
	points, found := RiskPoints(rule)
	if !found {
		return RiskContribution{}, fmt.Errorf(
			"unsupported risk rule %q",
			rule,
		)
	}

	contribution := RiskContribution{
		Rule:   rule,
		Points: points,
		Reason: strings.TrimSpace(reason),
	}

	if err := contribution.Validate(); err != nil {
		return RiskContribution{}, err
	}

	return contribution, nil
}

// Validate ensures that a contribution uses the exact configured score
// for its rule.
func (c RiskContribution) Validate() error {
	expectedPoints, found := RiskPoints(c.Rule)
	if !found {
		return fmt.Errorf(
			"unsupported risk rule %q",
			c.Rule,
		)
	}

	if c.Points != expectedPoints {
		return fmt.Errorf(
			"risk rule %q requires %d points, got %d",
			c.Rule,
			expectedPoints,
			c.Points,
		)
	}

	if strings.TrimSpace(c.Reason) == "" {
		return errors.New(
			"risk contribution reason must not be empty",
		)
	}

	return nil
}

// RiskPoints returns the fixed score associated with a risk rule.
func RiskPoints(rule RiskRule) (int, bool) {
	points, found := riskRulePoints[rule]

	return points, found
}

// ReachesQuarantineThreshold reports whether the workload must be
// quarantined.
func ReachesQuarantineThreshold(score int) bool {
	return score >= QuarantineThreshold
}

var riskRulePoints = map[RiskRule]int{
	RiskRuleUnauthorizedEndpoint: UnauthorizedEndpointPoints,
	RiskRuleFiveDeniedRequests:   FiveDeniedRequestsPoints,
	RiskRuleHighRequestRate:      HighRequestRatePoints,
	RiskRuleSensitiveEndpoint:    SensitiveEndpointPoints,
	RiskRuleAdministrative:       AdministrativePoints,
	RiskRuleHighlySensitive:      HighlySensitivePoints,
}
