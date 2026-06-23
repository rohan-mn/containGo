package controlplane

import (
	"context"
	"errors"
	"fmt"

	"containgo.local/containgo/internal/domain"
)

const incidentEvidenceEventLimit = 500

// incidentEvidence reconstructs the complete set of contributions that make
// up the workload's current score. Events are supplied newest first by the
// repository. The returned contributions are ordered oldest first so the
// incident tells a chronological story.
//
// Risk scores only increase until an administrator resets or releases the
// workload. Because every contribution has a positive, server-controlled
// value, the newest suffix whose points equal the current score is exactly the
// current risk cycle; older persisted events belong to an earlier cycle.
func incidentEvidence(
	events []domain.StoredEvent,
	score int,
) ([]domain.RiskContribution, error) {
	if score <= 0 {
		return nil, errors.New("incident score must be positive")
	}

	segments := make(
		[][]domain.RiskContribution,
		0,
	)
	total := 0

	for _, storedEvent := range events {
		if len(storedEvent.Contributions) == 0 {
			continue
		}

		segment := append(
			[]domain.RiskContribution(nil),
			storedEvent.Contributions...,
		)
		segmentPoints := 0

		for index, contribution := range segment {
			if err := contribution.Validate(); err != nil {
				return nil, fmt.Errorf(
					"validate contribution %d for event %q: %w",
					index,
					storedEvent.Event.RequestID,
					err,
				)
			}

			segmentPoints += contribution.Points
		}

		if total+segmentPoints > score {
			return nil, fmt.Errorf(
				"persisted evidence exceeds current score: collected %d, next event adds %d, score is %d",
				total,
				segmentPoints,
				score,
			)
		}

		segments = append(segments, segment)
		total += segmentPoints

		if total == score {
			break
		}
	}

	if total != score {
		return nil, fmt.Errorf(
			"persisted evidence totals %d points, want current score %d",
			total,
			score,
		)
	}

	reasons := make(
		[]domain.RiskContribution,
		0,
		len(segments)*2,
	)

	for index := len(segments) - 1; index >= 0; index-- {
		reasons = append(reasons, segments[index]...)
	}

	return reasons, nil
}

func (s *Service) loadIncidentEvidence(
	ctx context.Context,
	workloadID string,
	score int,
) ([]domain.RiskContribution, error) {
	events, err := s.events.ListByWorkload(
		ctx,
		workloadID,
		incidentEvidenceEventLimit,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"list events for incident evidence: %w",
			err,
		)
	}

	reasons, err := incidentEvidence(events, score)
	if err != nil {
		return nil, fmt.Errorf(
			"reconstruct incident evidence for workload %q: %w",
			workloadID,
			err,
		)
	}

	return reasons, nil
}
