package risk

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

// Window counts observations per key over a rolling time period.
//
// A Window is safe for concurrent use. Separate Window instances can
// be used for different measurements, such as all requests and denied
// requests.
type Window struct {
	mu       sync.Mutex
	duration time.Duration
	clock    Clock
	entries  map[string][]time.Time
}

// NewWindow creates an empty rolling counter.
func NewWindow(
	duration time.Duration,
	clock Clock,
) (*Window, error) {
	if duration <= 0 {
		return nil, errors.New(
			"window duration must be greater than zero",
		)
	}

	if clock == nil {
		return nil, errors.New(
			"clock must not be nil",
		)
	}

	return &Window{
		duration: duration,
		clock:    clock,
		entries:  make(map[string][]time.Time),
	}, nil
}

// Add records one observation for key and returns the number of
// observations still inside the rolling window, including the newly
// added observation.
func (w *Window) Add(key string) (int, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return 0, errors.New(
			"window key must not be empty",
		)
	}

	now := w.clock.Now().UTC()

	w.mu.Lock()
	defer w.mu.Unlock()

	observations := w.pruneLocked(key, now)
	observations = append(observations, now)
	w.entries[key] = observations

	return len(observations), nil
}

// Count returns the number of observations for key that remain inside
// the rolling window.
func (w *Window) Count(key string) (int, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return 0, errors.New(
			"window key must not be empty",
		)
	}

	now := w.clock.Now().UTC()

	w.mu.Lock()
	defer w.mu.Unlock()

	observations := w.pruneLocked(key, now)

	if len(observations) == 0 {
		delete(w.entries, key)

		return 0, nil
	}

	w.entries[key] = observations

	return len(observations), nil
}

// Restore replaces the observations for key with the supplied timestamps that
// still fall inside this rolling window. It returns the restored count.
func (w *Window) Restore(
	key string,
	observations []time.Time,
) (int, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return 0, errors.New(
			"window key must not be empty",
		)
	}

	now := w.clock.Now().UTC()
	cutoff := now.Add(-w.duration)
	restored := make(
		[]time.Time,
		0,
		len(observations),
	)

	for _, observedAt := range observations {
		if observedAt.IsZero() {
			return 0, errors.New(
				"observation timestamp must not be zero",
			)
		}

		observedAt = observedAt.UTC()
		if observedAt.After(now) {
			return 0, errors.New(
				"observation timestamp must not be in the future",
			)
		}

		if observedAt.Before(cutoff) {
			continue
		}

		restored = append(
			restored,
			observedAt,
		)
	}

	sort.Slice(
		restored,
		func(left, right int) bool {
			return restored[left].Before(
				restored[right],
			)
		},
	)

	w.mu.Lock()
	defer w.mu.Unlock()

	if len(restored) == 0 {
		delete(w.entries, key)
		return 0, nil
	}

	w.entries[key] = restored

	return len(restored), nil
}

// Reset removes every recorded observation for key.
func (w *Window) Reset(key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return errors.New(
			"window key must not be empty",
		)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	delete(w.entries, key)

	return nil
}

func (w *Window) pruneLocked(
	key string,
	now time.Time,
) []time.Time {
	observations := w.entries[key]
	cutoff := now.Add(-w.duration)

	firstIncluded := 0

	for firstIncluded < len(observations) &&
		observations[firstIncluded].Before(cutoff) {
		firstIncluded++
	}

	if firstIncluded == len(observations) {
		return nil
	}

	if firstIncluded == 0 {
		return observations
	}

	remaining := make(
		[]time.Time,
		len(observations)-firstIncluded,
	)
	copy(
		remaining,
		observations[firstIncluded:],
	)

	return remaining
}
