package controlplane

import (
	"strings"
	"testing"
	"time"

	"containgo.local/containgo/internal/domain"
)

func TestIncidentEvidenceReconstructsCurrentRiskCycle(t *testing.T) {
	events := []domain.StoredEvent{
		storedEvidenceEvent(
			"request-newest",
			domain.RiskRuleUnauthorizedEndpoint,
			domain.RiskRuleAdministrative,
		),
		storedEvidenceEvent(
			"request-older",
			domain.RiskRuleUnauthorizedEndpoint,
			domain.RiskRuleHighlySensitive,
		),
	}

	reasons, err := incidentEvidence(events, 125)
	if err != nil {
		t.Fatalf("incidentEvidence() unexpected error: %v", err)
	}

	if got := contributionPoints(reasons); got != 125 {
		t.Fatalf("evidence points = %d, want 125", got)
	}

	wantRules := []domain.RiskRule{
		domain.RiskRuleUnauthorizedEndpoint,
		domain.RiskRuleHighlySensitive,
		domain.RiskRuleUnauthorizedEndpoint,
		domain.RiskRuleAdministrative,
	}

	if len(reasons) != len(wantRules) {
		t.Fatalf("reason count = %d, want %d", len(reasons), len(wantRules))
	}

	for index, wantRule := range wantRules {
		if reasons[index].Rule != wantRule {
			t.Fatalf(
				"reason %d rule = %q, want %q",
				index,
				reasons[index].Rule,
				wantRule,
			)
		}
	}
}

func TestIncidentEvidenceExcludesEarlierResetCycle(t *testing.T) {
	events := []domain.StoredEvent{
		storedEvidenceEvent(
			"current-newest",
			domain.RiskRuleUnauthorizedEndpoint,
			domain.RiskRuleSensitiveEndpoint,
		),
		storedEvidenceEvent(
			"current-older",
			domain.RiskRuleHighRequestRate,
		),
		storedEvidenceEvent(
			"previous-cycle",
			domain.RiskRuleUnauthorizedEndpoint,
			domain.RiskRuleAdministrative,
		),
	}

	reasons, err := incidentEvidence(events, 75)
	if err != nil {
		t.Fatalf("incidentEvidence() unexpected error: %v", err)
	}

	if got := contributionPoints(reasons); got != 75 {
		t.Fatalf("evidence points = %d, want 75", got)
	}

	for _, reason := range reasons {
		if reason.Rule == domain.RiskRuleAdministrative {
			t.Fatal("evidence included a contribution from the previous risk cycle")
		}
	}
}

func TestIncidentEvidenceRejectsIncompleteHistory(t *testing.T) {
	events := []domain.StoredEvent{
		storedEvidenceEvent(
			"only-event",
			domain.RiskRuleUnauthorizedEndpoint,
		),
	}

	_, err := incidentEvidence(events, 70)
	if err == nil || !strings.Contains(err.Error(), "totals 25 points") {
		t.Fatalf("incidentEvidence() error = %v, want incomplete-evidence error", err)
	}
}

func TestIncidentEvidenceRejectsOvershoot(t *testing.T) {
	events := []domain.StoredEvent{
		storedEvidenceEvent(
			"too-large",
			domain.RiskRuleUnauthorizedEndpoint,
			domain.RiskRuleAdministrative,
		),
	}

	_, err := incidentEvidence(events, 50)
	if err == nil || !strings.Contains(err.Error(), "exceeds current score") {
		t.Fatalf("incidentEvidence() error = %v, want overshoot error", err)
	}
}

func storedEvidenceEvent(
	requestID string,
	rules ...domain.RiskRule,
) domain.StoredEvent {
	contributions := make([]domain.RiskContribution, 0, len(rules))

	for _, rule := range rules {
		contribution, err := domain.NewRiskContribution(
			rule,
			"test contribution for "+string(rule),
		)
		if err != nil {
			panic(err)
		}

		contributions = append(contributions, contribution)
	}

	return domain.StoredEvent{
		Event: domain.SecurityEvent{
			ID:         1,
			RequestID:  requestID,
			WorkloadID: domain.SPIFFEIDReportClient,
			Method:     "GET",
			Path:       "/api/test",
			Decision:   domain.DecisionDenied,
			StatusCode: 403,
			Reason:     "test denial",
			OccurredAt: time.Date(2026, time.June, 22, 0, 0, 0, 0, time.UTC),
		},
		Contributions: contributions,
		CreatedAt:     time.Date(2026, time.June, 22, 0, 0, 1, 0, time.UTC),
	}
}

func contributionPoints(contributions []domain.RiskContribution) int {
	total := 0
	for _, contribution := range contributions {
		total += contribution.Points
	}
	return total
}
