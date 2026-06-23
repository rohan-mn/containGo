package domain

import (
	"strings"
	"testing"
)

func TestRiskPoints(t *testing.T) {
	tests := []struct {
		name       string
		rule       RiskRule
		wantPoints int
	}{
		{
			name:       "unauthorized endpoint",
			rule:       RiskRuleUnauthorizedEndpoint,
			wantPoints: 25,
		},
		{
			name:       "five denied requests",
			rule:       RiskRuleFiveDeniedRequests,
			wantPoints: 25,
		},
		{
			name:       "high request rate",
			rule:       RiskRuleHighRequestRate,
			wantPoints: 20,
		},
		{
			name:       "sensitive endpoint",
			rule:       RiskRuleSensitiveEndpoint,
			wantPoints: 30,
		},
		{
			name:       "administrative endpoint",
			rule:       RiskRuleAdministrative,
			wantPoints: 35,
		},
		{
			name:       "highly sensitive endpoint",
			rule:       RiskRuleHighlySensitive,
			wantPoints: 40,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, found := RiskPoints(tt.rule)

			if !found {
				t.Fatalf(
					"RiskPoints(%q) found = false, want true",
					tt.rule,
				)
			}

			if got != tt.wantPoints {
				t.Fatalf(
					"RiskPoints(%q) = %d, want %d",
					tt.rule,
					got,
					tt.wantPoints,
				)
			}
		})
	}

	if _, found := RiskPoints(RiskRule("unknown")); found {
		t.Fatal(
			"RiskPoints(unknown) found = true, want false",
		)
	}
}

func TestNewRiskContribution(t *testing.T) {
	contribution, err := NewRiskContribution(
		RiskRuleHighlySensitive,
		"  attempted /api/payment-details  ",
	)
	if err != nil {
		t.Fatalf(
			"NewRiskContribution() unexpected error: %v",
			err,
		)
	}

	if contribution.Points != HighlySensitivePoints {
		t.Fatalf(
			"NewRiskContribution() points = %d, want %d",
			contribution.Points,
			HighlySensitivePoints,
		)
	}

	if contribution.Reason !=
		"attempted /api/payment-details" {
		t.Fatalf(
			"NewRiskContribution() reason = %q",
			contribution.Reason,
		)
	}

	_, err = NewRiskContribution(
		RiskRule("unknown"),
		"reason",
	)
	if err == nil ||
		!strings.Contains(err.Error(), "unsupported risk rule") {
		t.Fatalf(
			"NewRiskContribution(unknown) error = %v",
			err,
		)
	}

	_, err = NewRiskContribution(
		RiskRuleSensitiveEndpoint,
		" ",
	)
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"reason must not be empty",
		) {
		t.Fatalf(
			"NewRiskContribution(empty reason) error = %v",
			err,
		)
	}
}

func TestRiskContributionValidateRejectsTamperedPoints(
	t *testing.T,
) {
	contribution := RiskContribution{
		Rule:   RiskRuleAdministrative,
		Points: 100,
		Reason: "attempted /api/admin/config",
	}

	err := contribution.Validate()

	if err == nil ||
		!strings.Contains(
			err.Error(),
			"requires 35 points, got 100",
		) {
		t.Fatalf(
			"Validate() error = %v",
			err,
		)
	}
}

func TestReachesQuarantineThreshold(t *testing.T) {
	tests := []struct {
		score int
		want  bool
	}{
		{
			score: -1,
			want:  false,
		},
		{
			score: 0,
			want:  false,
		},
		{
			score: 69,
			want:  false,
		},
		{
			score: 70,
			want:  true,
		},
		{
			score: 100,
			want:  true,
		},
	}

	for _, tt := range tests {
		if got := ReachesQuarantineThreshold(
			tt.score,
		); got != tt.want {
			t.Errorf(
				"ReachesQuarantineThreshold(%d) = %t, want %t",
				tt.score,
				got,
				tt.want,
			)
		}
	}
}
