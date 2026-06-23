package risk

import (
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(now time.Time) *fakeClock {
	return &fakeClock{
		now: now,
	}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *fakeClock) Advance(
	duration time.Duration,
) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(duration)
}

func TestNewWindowValidation(t *testing.T) {
	clock := newFakeClock(time.Now())

	if _, err := NewWindow(0, clock); err == nil {
		t.Fatal(
			"NewWindow(0) error = nil, want error",
		)
	}

	if _, err := NewWindow(
		time.Minute,
		nil,
	); err == nil {
		t.Fatal(
			"NewWindow(nil clock) error = nil, want error",
		)
	}
}

func TestWindowRollingBoundary(t *testing.T) {
	start := time.Date(
		2026,
		time.June,
		20,
		12,
		0,
		0,
		0,
		time.UTC,
	)

	clock := newFakeClock(start)

	window, err := NewWindow(
		time.Minute,
		clock,
	)
	if err != nil {
		t.Fatalf(
			"NewWindow() unexpected error: %v",
			err,
		)
	}

	count, err := window.Add("report-client")
	if err != nil || count != 1 {
		t.Fatalf(
			"Add() = (%d, %v), want (1, nil)",
			count,
			err,
		)
	}

	clock.Advance(59 * time.Second)

	assertWindowCount(
		t,
		window,
		"report-client",
		1,
	)

	// Exactly 60 seconds old remains inside the window.
	clock.Advance(time.Second)

	assertWindowCount(
		t,
		window,
		"report-client",
		1,
	)

	// Once it is older than 60 seconds, it is removed.
	clock.Advance(time.Nanosecond)

	assertWindowCount(
		t,
		window,
		"report-client",
		0,
	)
}

func TestWindowSeparatesKeysAndResets(
	t *testing.T,
) {
	clock := newFakeClock(time.Now().UTC())

	window, err := NewWindow(
		time.Minute,
		clock,
	)
	if err != nil {
		t.Fatalf(
			"NewWindow() unexpected error: %v",
			err,
		)
	}

	for range 3 {
		if _, err := window.Add(
			"report-client",
		); err != nil {
			t.Fatalf(
				"Add(report-client): %v",
				err,
			)
		}
	}

	if _, err := window.Add(
		"order-client",
	); err != nil {
		t.Fatalf(
			"Add(order-client): %v",
			err,
		)
	}

	assertWindowCount(
		t,
		window,
		"report-client",
		3,
	)

	assertWindowCount(
		t,
		window,
		"order-client",
		1,
	)

	if err := window.Reset(
		"report-client",
	); err != nil {
		t.Fatalf(
			"Reset() unexpected error: %v",
			err,
		)
	}

	assertWindowCount(
		t,
		window,
		"report-client",
		0,
	)

	assertWindowCount(
		t,
		window,
		"order-client",
		1,
	)
}

func TestWindowRejectsEmptyKey(t *testing.T) {
	clock := newFakeClock(time.Now().UTC())

	window, err := NewWindow(
		time.Minute,
		clock,
	)
	if err != nil {
		t.Fatalf(
			"NewWindow() unexpected error: %v",
			err,
		)
	}

	if _, err := window.Add(" "); err == nil {
		t.Fatal(
			"Add(empty key) error = nil, want error",
		)
	}

	if _, err := window.Count(""); err == nil {
		t.Fatal(
			"Count(empty key) error = nil, want error",
		)
	}

	if err := window.Reset(" "); err == nil {
		t.Fatal(
			"Reset(empty key) error = nil, want error",
		)
	}
}

func TestWindowConcurrentAdd(t *testing.T) {
	clock := newFakeClock(time.Now().UTC())

	window, err := NewWindow(
		time.Minute,
		clock,
	)
	if err != nil {
		t.Fatalf(
			"NewWindow() unexpected error: %v",
			err,
		)
	}

	const workers = 100

	var waitGroup sync.WaitGroup
	waitGroup.Add(workers)

	for range workers {
		go func() {
			defer waitGroup.Done()

			if _, addErr := window.Add(
				"report-client",
			); addErr != nil {
				t.Errorf(
					"Add() unexpected error: %v",
					addErr,
				)
			}
		}()
	}

	waitGroup.Wait()

	assertWindowCount(
		t,
		window,
		"report-client",
		workers,
	)
}

func assertWindowCount(
	t *testing.T,
	window *Window,
	key string,
	want int,
) {
	t.Helper()

	got, err := window.Count(key)
	if err != nil {
		t.Fatalf(
			"Count(%q) unexpected error: %v",
			key,
			err,
		)
	}

	if got != want {
		t.Fatalf(
			"Count(%q) = %d, want %d",
			key,
			got,
			want,
		)
	}
}
