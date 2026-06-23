package risk

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"containgo.local/containgo/internal/domain"
)

func TestNewEngineValidation(t *testing.T) {
	engine, err := NewEngine(nil)

	if err == nil {
		t.Fatal(
			"NewEngine(nil) error = nil, want error",
		)
	}

	if engine != nil {
		t.Fatal(
			"NewEngine(nil) returned a non-nil engine",
		)
	}
}

func TestEngineNormalRequest(t *testing.T) {
	clock := newFakeClock(
		time.Date(
			2026,
			time.June,
			20,
			12,
			0,
			0,
			0,
			time.UTC,
		),
	)

	engine := newTestEngine(t, clock)

	result, err := engine.Evaluate(
		newTestSecurityEvent(
			clock,
			"req-order-1",
			domain.SPIFFEIDOrderClient,
			"/api/orders",
			domain.DecisionAllowed,
		),
	)
	if err != nil {
		t.Fatalf(
			"Evaluate() unexpected error: %v",
			err,
		)
	}

	if result.Score != 0 {
		t.Fatalf(
			"Score = %d, want 0",
			result.Score,
		)
	}

	if result.RequestCount != 1 {
		t.Fatalf(
			"RequestCount = %d, want 1",
			result.RequestCount,
		)
	}

	if result.DeniedCount != 0 {
		t.Fatalf(
			"DeniedCount = %d, want 0",
			result.DeniedCount,
		)
	}

	if len(result.Contributions) != 0 {
		t.Fatalf(
			"Contributions = %v, want none",
			result.Contributions,
		)
	}

	if result.Quarantined {
		t.Fatal(
			"normal order-client request caused quarantine",
		)
	}
}

func TestEngineUnauthorizedEndpoint(t *testing.T) {
	clock := newFakeClock(time.Now().UTC())
	engine := newTestEngine(t, clock)

	result, err := engine.Evaluate(
		newTestSecurityEvent(
			clock,
			"req-report-orders",
			domain.SPIFFEIDReportClient,
			"/api/orders",
			domain.DecisionDenied,
		),
	)
	if err != nil {
		t.Fatalf(
			"Evaluate() unexpected error: %v",
			err,
		)
	}

	if result.Score != domain.UnauthorizedEndpointPoints {
		t.Fatalf(
			"Score = %d, want %d",
			result.Score,
			domain.UnauthorizedEndpointPoints,
		)
	}

	assertContainsRiskRule(
		t,
		result.Contributions,
		domain.RiskRuleUnauthorizedEndpoint,
	)
}

func TestEngineSensitiveAttemptsTriggerQuarantine(
	t *testing.T,
) {
	clock := newFakeClock(time.Now().UTC())
	engine := newTestEngine(t, clock)

	first, err := engine.Evaluate(
		newTestSecurityEvent(
			clock,
			"req-payment",
			domain.SPIFFEIDReportClient,
			"/api/payment-details",
			domain.DecisionDenied,
		),
	)
	if err != nil {
		t.Fatalf(
			"first Evaluate() unexpected error: %v",
			err,
		)
	}

	// Unauthorized 25 + highly sensitive 40 = 65.
	if first.Score != 65 {
		t.Fatalf(
			"first score = %d, want 65",
			first.Score,
		)
	}

	if first.Quarantined {
		t.Fatal(
			"score 65 caused quarantine, want active",
		)
	}

	assertContainsRiskRule(
		t,
		first.Contributions,
		domain.RiskRuleUnauthorizedEndpoint,
	)

	assertContainsRiskRule(
		t,
		first.Contributions,
		domain.RiskRuleHighlySensitive,
	)

	second, err := engine.Evaluate(
		newTestSecurityEvent(
			clock,
			"req-customers",
			domain.SPIFFEIDReportClient,
			"/api/customers",
			domain.DecisionDenied,
		),
	)
	if err != nil {
		t.Fatalf(
			"second Evaluate() unexpected error: %v",
			err,
		)
	}

	// Previous 65 + unauthorized 25 + sensitive 30 = 120.
	if second.Score != 120 {
		t.Fatalf(
			"second score = %d, want 120",
			second.Score,
		)
	}

	if !second.Quarantined {
		t.Fatal(
			"score 120 did not cause quarantine",
		)
	}

	if !second.NewlyQuarantined {
		t.Fatal(
			"NewlyQuarantined = false, want true",
		)
	}

	third, err := engine.Evaluate(
		newTestSecurityEvent(
			clock,
			"req-admin-after-quarantine",
			domain.SPIFFEIDReportClient,
			"/api/admin/config",
			domain.DecisionDenied,
		),
	)
	if err != nil {
		t.Fatalf(
			"third Evaluate() unexpected error: %v",
			err,
		)
	}

	if third.Score != 120 {
		t.Fatalf(
			"post-quarantine score = %d, want 120",
			third.Score,
		)
	}

	if len(third.Contributions) != 0 {
		t.Fatalf(
			"post-quarantine contributions = %v, want none",
			third.Contributions,
		)
	}

	if third.NewlyQuarantined {
		t.Fatal(
			"NewlyQuarantined remained true after quarantine",
		)
	}
}

func TestEngineDeniedThresholdIsEdgeTriggered(
	t *testing.T,
) {
	clock := newFakeClock(time.Now().UTC())
	engine := newTestEngine(t, clock)

	var result EvaluationResult

	// The endpoint is normally authorized. The denied decision could
	// represent a temporary enforcement or fail-closed response.
	for index := range 5 {
		var err error

		result, err = engine.Evaluate(
			newTestSecurityEvent(
				clock,
				requestID("denied", index),
				domain.SPIFFEIDReportClient,
				"/api/reports",
				domain.DecisionDenied,
			),
		)
		if err != nil {
			t.Fatalf(
				"Evaluate() request %d: %v",
				index+1,
				err,
			)
		}
	}

	if result.Score != domain.FiveDeniedRequestsPoints {
		t.Fatalf(
			"score after five denials = %d, want %d",
			result.Score,
			domain.FiveDeniedRequestsPoints,
		)
	}

	assertContainsRiskRule(
		t,
		result.Contributions,
		domain.RiskRuleFiveDeniedRequests,
	)

	sixth, err := engine.Evaluate(
		newTestSecurityEvent(
			clock,
			"denied-6",
			domain.SPIFFEIDReportClient,
			"/api/reports",
			domain.DecisionDenied,
		),
	)
	if err != nil {
		t.Fatalf(
			"sixth Evaluate() unexpected error: %v",
			err,
		)
	}

	if sixth.Score != domain.FiveDeniedRequestsPoints {
		t.Fatalf(
			"score after sixth denial = %d, want %d",
			sixth.Score,
			domain.FiveDeniedRequestsPoints,
		)
	}

	if len(sixth.Contributions) != 0 {
		t.Fatalf(
			"sixth contributions = %v, want none",
			sixth.Contributions,
		)
	}

	// Expire the previous denial window and cross the threshold again.
	clock.Advance(61 * time.Second)

	for index := range 5 {
		var evaluationErr error

		result, evaluationErr = engine.Evaluate(
			newTestSecurityEvent(
				clock,
				requestID("second-window-denied", index),
				domain.SPIFFEIDReportClient,
				"/api/reports",
				domain.DecisionDenied,
			),
		)
		if evaluationErr != nil {
			t.Fatalf(
				"second-window Evaluate() request %d: %v",
				index+1,
				evaluationErr,
			)
		}
	}

	if result.Score != 2*domain.FiveDeniedRequestsPoints {
		t.Fatalf(
			"score after second denial window = %d, want %d",
			result.Score,
			2*domain.FiveDeniedRequestsPoints,
		)
	}
}

func TestEngineHighRequestRateIsEdgeTriggered(
	t *testing.T,
) {
	clock := newFakeClock(time.Now().UTC())
	engine := newTestEngine(t, clock)

	var result EvaluationResult

	// "More than 30" means the 31st request triggers the rule.
	for index := range 31 {
		var err error

		result, err = engine.Evaluate(
			newTestSecurityEvent(
				clock,
				requestID("order", index),
				domain.SPIFFEIDOrderClient,
				"/api/orders",
				domain.DecisionAllowed,
			),
		)
		if err != nil {
			t.Fatalf(
				"Evaluate() request %d: %v",
				index+1,
				err,
			)
		}
	}

	if result.RequestCount != 31 {
		t.Fatalf(
			"RequestCount = %d, want 31",
			result.RequestCount,
		)
	}

	if result.Score != domain.HighRequestRatePoints {
		t.Fatalf(
			"score after 31 requests = %d, want %d",
			result.Score,
			domain.HighRequestRatePoints,
		)
	}

	assertContainsRiskRule(
		t,
		result.Contributions,
		domain.RiskRuleHighRequestRate,
	)

	request32, err := engine.Evaluate(
		newTestSecurityEvent(
			clock,
			"order-32",
			domain.SPIFFEIDOrderClient,
			"/api/orders",
			domain.DecisionAllowed,
		),
	)
	if err != nil {
		t.Fatalf(
			"32nd Evaluate() unexpected error: %v",
			err,
		)
	}

	if request32.Score != domain.HighRequestRatePoints {
		t.Fatalf(
			"score after request 32 = %d, want %d",
			request32.Score,
			domain.HighRequestRatePoints,
		)
	}

	if len(request32.Contributions) != 0 {
		t.Fatalf(
			"request 32 contributions = %v, want none",
			request32.Contributions,
		)
	}

	clock.Advance(61 * time.Second)

	// Cross the rate threshold again in a fresh rolling window.
	for index := range 31 {
		var evaluationErr error

		result, evaluationErr = engine.Evaluate(
			newTestSecurityEvent(
				clock,
				requestID("new-window-order", index),
				domain.SPIFFEIDOrderClient,
				"/api/orders",
				domain.DecisionAllowed,
			),
		)
		if evaluationErr != nil {
			t.Fatalf(
				"fresh-window Evaluate() request %d: %v",
				index+1,
				evaluationErr,
			)
		}
	}

	if result.Score != 2*domain.HighRequestRatePoints {
		t.Fatalf(
			"score after second request window = %d, want %d",
			result.Score,
			2*domain.HighRequestRatePoints,
		)
	}
}

func TestEngineReset(t *testing.T) {
	clock := newFakeClock(time.Now().UTC())
	engine := newTestEngine(t, clock)

	_, err := engine.Evaluate(
		newTestSecurityEvent(
			clock,
			"req-before-reset",
			domain.SPIFFEIDReportClient,
			"/api/payment-details",
			domain.DecisionDenied,
		),
	)
	if err != nil {
		t.Fatalf(
			"Evaluate() unexpected error: %v",
			err,
		)
	}

	beforeReset, found := engine.Snapshot(
		domain.SPIFFEIDReportClient,
	)
	if !found {
		t.Fatal(
			"Snapshot() found = false before reset",
		)
	}

	if beforeReset.Score != 65 {
		t.Fatalf(
			"score before reset = %d, want 65",
			beforeReset.Score,
		)
	}

	if err := engine.Reset(
		domain.SPIFFEIDReportClient,
	); err != nil {
		t.Fatalf(
			"Reset() unexpected error: %v",
			err,
		)
	}

	if _, found := engine.Snapshot(
		domain.SPIFFEIDReportClient,
	); found {
		t.Fatal(
			"Snapshot() found = true after reset",
		)
	}

	afterReset, err := engine.Evaluate(
		newTestSecurityEvent(
			clock,
			"req-after-reset",
			domain.SPIFFEIDReportClient,
			"/api/reports",
			domain.DecisionAllowed,
		),
	)
	if err != nil {
		t.Fatalf(
			"Evaluate() after reset: %v",
			err,
		)
	}

	if afterReset.Score != 0 {
		t.Fatalf(
			"score after reset = %d, want 0",
			afterReset.Score,
		)
	}

	if afterReset.RequestCount != 1 {
		t.Fatalf(
			"request count after reset = %d, want 1",
			afterReset.RequestCount,
		)
	}

	if afterReset.DeniedCount != 0 {
		t.Fatalf(
			"denied count after reset = %d, want 0",
			afterReset.DeniedCount,
		)
	}
}

func TestEngineRejectsUnknownWorkload(
	t *testing.T,
) {
	clock := newFakeClock(time.Now().UTC())
	engine := newTestEngine(t, clock)

	event := newTestSecurityEvent(
		clock,
		"req-unknown",
		"spiffe://containgo.local/ns/containgo/sa/unknown",
		"/api/orders",
		domain.DecisionDenied,
	)

	_, err := engine.Evaluate(event)

	if err == nil {
		t.Fatal(
			"Evaluate(unknown workload) error = nil, want error",
		)
	}

	if !strings.Contains(
		err.Error(),
		"unknown workload SPIFFE ID",
	) {
		t.Fatalf(
			"Evaluate() error = %v",
			err,
		)
	}
}

func TestEngineConcurrentEvaluation(t *testing.T) {
	clock := newFakeClock(time.Now().UTC())
	engine := newTestEngine(t, clock)

	const requestCount = 100

	var waitGroup sync.WaitGroup
	waitGroup.Add(requestCount)

	for index := range requestCount {
		go func(requestNumber int) {
			defer waitGroup.Done()

			_, err := engine.Evaluate(
				newTestSecurityEvent(
					clock,
					requestID("concurrent", requestNumber),
					domain.SPIFFEIDOrderClient,
					"/api/orders",
					domain.DecisionAllowed,
				),
			)
			if err != nil {
				t.Errorf(
					"Evaluate() request %d: %v",
					requestNumber,
					err,
				)
			}
		}(index)
	}

	waitGroup.Wait()

	snapshot, found := engine.Snapshot(
		domain.SPIFFEIDOrderClient,
	)
	if !found {
		t.Fatal(
			"Snapshot() found = false",
		)
	}

	if snapshot.Score != domain.HighRequestRatePoints {
		t.Fatalf(
			"concurrent score = %d, want %d",
			snapshot.Score,
			domain.HighRequestRatePoints,
		)
	}
}

func newTestEngine(
	t *testing.T,
	clock Clock,
) *Engine {
	t.Helper()

	engine, err := NewEngine(clock)
	if err != nil {
		t.Fatalf(
			"NewEngine() unexpected error: %v",
			err,
		)
	}

	return engine
}

func newTestSecurityEvent(
	clock Clock,
	requestID string,
	workloadID string,
	path string,
	decision domain.SecurityDecision,
) domain.SecurityEvent {
	statusCode := http.StatusOK
	reason := ""

	if decision == domain.DecisionDenied {
		statusCode = http.StatusForbidden
		reason = "denied by authorization policy"
	}

	return domain.SecurityEvent{
		RequestID:  requestID,
		WorkloadID: workloadID,
		Method:     http.MethodGet,
		Path:       path,
		Decision:   decision,
		StatusCode: statusCode,
		Reason:     reason,
		OccurredAt: clock.Now(),
	}
}

func requestID(
	prefix string,
	index int,
) string {
	return prefix + "-" + string(rune('a'+index))
}

func assertContainsRiskRule(
	t *testing.T,
	contributions []domain.RiskContribution,
	want domain.RiskRule,
) {
	t.Helper()

	for _, contribution := range contributions {
		if contribution.Rule == want {
			return
		}
	}

	t.Fatalf(
		"contributions %v do not contain rule %q",
		contributions,
		want,
	)
}
