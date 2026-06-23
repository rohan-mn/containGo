package repository

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"containgo.local/containgo/internal/domain"
	"containgo.local/containgo/internal/testutil"
)

func TestSQLiteEventRepositoryCreateAndList(
	t *testing.T,
) {
	db := testutil.OpenSQLite(t)
	seedWorkloads(t, db)

	repository, err := NewSQLiteEventRepository(db)
	if err != nil {
		t.Fatalf(
			"NewSQLiteEventRepository() error: %v",
			err,
		)
	}

	occurredAt := repositoryTestTime()
	createdAt := occurredAt.Add(time.Second)

	event := deniedEvent(
		"req-payment-1",
		"/api/payment-details",
		occurredAt,
	)

	unauthorized := mustContribution(
		t,
		domain.RiskRuleUnauthorizedEndpoint,
		"workload is not authorized for the requested endpoint",
	)

	highlySensitive := mustContribution(
		t,
		domain.RiskRuleHighlySensitive,
		"attempted access to /api/payment-details",
	)

	stored, err := repository.Create(
		context.Background(),
		event,
		[]domain.RiskContribution{
			unauthorized,
			highlySensitive,
		},
		createdAt,
	)
	if err != nil {
		t.Fatalf(
			"Create() unexpected error: %v",
			err,
		)
	}

	if stored.Event.ID <= 0 {
		t.Fatalf(
			"stored event ID = %d, want positive value",
			stored.Event.ID,
		)
	}

	if stored.TotalContributionPoints() != 65 {
		t.Fatalf(
			"contribution points = %d, want 65",
			stored.TotalContributionPoints(),
		)
	}

	events, err := repository.ListByWorkload(
		context.Background(),
		domain.SPIFFEIDReportClient,
		10,
	)
	if err != nil {
		t.Fatalf(
			"ListByWorkload() unexpected error: %v",
			err,
		)
	}

	if len(events) != 1 {
		t.Fatalf(
			"event count = %d, want 1",
			len(events),
		)
	}

	got := events[0]

	if got.Event.RequestID != event.RequestID {
		t.Fatalf(
			"request ID = %q, want %q",
			got.Event.RequestID,
			event.RequestID,
		)
	}

	if len(got.Contributions) != 2 {
		t.Fatalf(
			"contribution count = %d, want 2",
			len(got.Contributions),
		)
	}

	if got.TotalContributionPoints() != 65 {
		t.Fatalf(
			"listed contribution points = %d, want 65",
			got.TotalContributionPoints(),
		)
	}
}

func TestSQLiteEventRepositoryTimelineOrdering(
	t *testing.T,
) {
	db := testutil.OpenSQLite(t)
	seedWorkloads(t, db)

	repository, err := NewSQLiteEventRepository(db)
	if err != nil {
		t.Fatalf(
			"NewSQLiteEventRepository() error: %v",
			err,
		)
	}

	start := repositoryTestTime()

	for index := range 3 {
		event := deniedEvent(
			"req-timeline-"+string(rune('1'+index)),
			"/api/customers",
			start.Add(time.Duration(index)*time.Second),
		)

		_, err = repository.Create(
			context.Background(),
			event,
			nil,
			event.OccurredAt.Add(time.Millisecond),
		)
		if err != nil {
			t.Fatalf(
				"Create() event %d: %v",
				index,
				err,
			)
		}
	}

	events, err := repository.ListByWorkload(
		context.Background(),
		domain.SPIFFEIDReportClient,
		2,
	)
	if err != nil {
		t.Fatalf(
			"ListByWorkload() unexpected error: %v",
			err,
		)
	}

	if len(events) != 2 {
		t.Fatalf(
			"event count = %d, want 2",
			len(events),
		)
	}

	if events[0].Event.RequestID != "req-timeline-3" {
		t.Fatalf(
			"first request = %q, want req-timeline-3",
			events[0].Event.RequestID,
		)
	}

	if events[1].Event.RequestID != "req-timeline-2" {
		t.Fatalf(
			"second request = %q, want req-timeline-2",
			events[1].Event.RequestID,
		)
	}
}

func TestSQLiteEventRepositoryDuplicateRequest(
	t *testing.T,
) {
	db := testutil.OpenSQLite(t)
	seedWorkloads(t, db)

	repository, err := NewSQLiteEventRepository(db)
	if err != nil {
		t.Fatalf(
			"NewSQLiteEventRepository() error: %v",
			err,
		)
	}

	now := repositoryTestTime()
	event := deniedEvent(
		"req-duplicate",
		"/api/customers",
		now,
	)

	contribution := mustContribution(
		t,
		domain.RiskRuleSensitiveEndpoint,
		"attempted access to /api/customers",
	)

	_, err = repository.Create(
		context.Background(),
		event,
		[]domain.RiskContribution{contribution},
		now.Add(time.Second),
	)
	if err != nil {
		t.Fatalf(
			"first Create() unexpected error: %v",
			err,
		)
	}

	_, err = repository.Create(
		context.Background(),
		event,
		[]domain.RiskContribution{contribution},
		now.Add(2*time.Second),
	)

	if !errors.Is(err, ErrConflict) {
		t.Fatalf(
			"duplicate Create() error = %v, want ErrConflict",
			err,
		)
	}

	var eventCount int

	err = db.QueryRow(
		`
			SELECT COUNT(*)
			FROM security_events
			WHERE request_id = ?
		`,
		event.RequestID,
	).Scan(&eventCount)
	if err != nil {
		t.Fatalf(
			"count events: %v",
			err,
		)
	}

	if eventCount != 1 {
		t.Fatalf(
			"event count = %d, want 1",
			eventCount,
		)
	}

	var contributionCount int

	err = db.QueryRow(
		`
			SELECT COUNT(*)
			FROM risk_contributions
		`,
	).Scan(&contributionCount)
	if err != nil {
		t.Fatalf(
			"count contributions: %v",
			err,
		)
	}

	if contributionCount != 1 {
		t.Fatalf(
			"contribution count = %d, want 1",
			contributionCount,
		)
	}
}

func TestSQLiteEventRepositoryCountDeniedSince(
	t *testing.T,
) {
	db := testutil.OpenSQLite(t)
	seedWorkloads(t, db)

	repository, err := NewSQLiteEventRepository(db)
	if err != nil {
		t.Fatalf(
			"NewSQLiteEventRepository() error: %v",
			err,
		)
	}

	start := repositoryTestTime()

	for index := range 3 {
		event := deniedEvent(
			"req-denied-"+string(rune('1'+index)),
			"/api/reports",
			start.Add(time.Duration(index)*time.Second),
		)

		_, err = repository.Create(
			context.Background(),
			event,
			nil,
			event.OccurredAt,
		)
		if err != nil {
			t.Fatalf(
				"Create() denied event %d: %v",
				index,
				err,
			)
		}
	}

	allowed := domain.SecurityEvent{
		RequestID:  "req-allowed",
		WorkloadID: domain.SPIFFEIDReportClient,
		Method:     http.MethodGet,
		Path:       "/api/reports",
		Decision:   domain.DecisionAllowed,
		StatusCode: http.StatusOK,
		OccurredAt: start.Add(3 * time.Second),
	}

	_, err = repository.Create(
		context.Background(),
		allowed,
		nil,
		allowed.OccurredAt,
	)
	if err != nil {
		t.Fatalf(
			"Create() allowed event: %v",
			err,
		)
	}

	count, err := repository.CountDeniedSince(
		context.Background(),
		domain.SPIFFEIDReportClient,
		start.Add(time.Second),
	)
	if err != nil {
		t.Fatalf(
			"CountDeniedSince() unexpected error: %v",
			err,
		)
	}

	if count != 2 {
		t.Fatalf(
			"denied count = %d, want 2",
			count,
		)
	}
}

func TestSQLiteEventRepositoryMissingWorkload(
	t *testing.T,
) {
	db := testutil.OpenSQLite(t)

	repository, err := NewSQLiteEventRepository(db)
	if err != nil {
		t.Fatalf(
			"NewSQLiteEventRepository() error: %v",
			err,
		)
	}

	event := deniedEvent(
		"req-unseeded",
		"/api/customers",
		repositoryTestTime(),
	)

	_, err = repository.Create(
		context.Background(),
		event,
		nil,
		event.OccurredAt,
	)

	if !errors.Is(err, ErrNotFound) {
		t.Fatalf(
			"Create(unseeded workload) error = %v, want ErrNotFound",
			err,
		)
	}
}

func TestSQLiteEventRepositoryValidation(
	t *testing.T,
) {
	db := testutil.OpenSQLite(t)
	seedWorkloads(t, db)

	repository, err := NewSQLiteEventRepository(db)
	if err != nil {
		t.Fatalf(
			"NewSQLiteEventRepository() error: %v",
			err,
		)
	}

	event := deniedEvent(
		"req-validation",
		"/api/customers",
		repositoryTestTime(),
	)

	_, err = repository.Create(
		nil,
		event,
		nil,
		event.OccurredAt,
	)
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"context must not be nil",
		) {
		t.Fatalf(
			"Create(nil context) error = %v",
			err,
		)
	}

	_, err = repository.ListByWorkload(
		context.Background(),
		domain.SPIFFEIDReportClient,
		0,
	)
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"limit must be between 1 and 500",
		) {
		t.Fatalf(
			"ListByWorkload(limit 0) error = %v",
			err,
		)
	}

	_, err = repository.CountDeniedSince(
		context.Background(),
		domain.SPIFFEIDReportClient,
		time.Time{},
	)
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"since timestamp must not be zero",
		) {
		t.Fatalf(
			"CountDeniedSince(zero time) error = %v",
			err,
		)
	}
}
func seedWorkloads(
	t *testing.T,
	db *sql.DB,
) {
	t.Helper()

	repository, err := NewSQLiteWorkloadRepository(
		db,
	)
	if err != nil {
		t.Fatalf(
			"NewSQLiteWorkloadRepository() error: %v",
			err,
		)
	}

	err = repository.EnsureKnown(
		context.Background(),
		repositoryTestTime(),
	)
	if err != nil {
		t.Fatalf(
			"EnsureKnown() error: %v",
			err,
		)
	}
}

func deniedEvent(
	requestID string,
	path string,
	occurredAt time.Time,
) domain.SecurityEvent {
	return domain.SecurityEvent{
		RequestID:  requestID,
		WorkloadID: domain.SPIFFEIDReportClient,
		Method:     http.MethodGet,
		Path:       path,
		Decision:   domain.DecisionDenied,
		StatusCode: http.StatusForbidden,
		Reason:     "denied by authorization policy",
		OccurredAt: occurredAt,
	}
}

func mustContribution(
	t *testing.T,
	rule domain.RiskRule,
	reason string,
) domain.RiskContribution {
	t.Helper()

	contribution, err := domain.NewRiskContribution(
		rule,
		reason,
	)
	if err != nil {
		t.Fatalf(
			"NewRiskContribution() error: %v",
			err,
		)
	}

	return contribution
}

func repositoryTestTime() time.Time {
	return time.Date(
		2026,
		time.June,
		20,
		12,
		0,
		0,
		0,
		time.UTC,
	)
}
