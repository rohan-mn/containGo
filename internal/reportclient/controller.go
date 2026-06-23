package reportclient

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Mode controls the request behavior of the Report Client.
type Mode string

const (
	ModeNormal Mode = "normal"
	ModeAttack Mode = "attack"
	ModeRapid  Mode = "rapid"
	ModePaused Mode = "paused"
)

// Snapshot is the current Report Client mode and runtime activity summary.
type Snapshot struct {
	Mode          Mode       `json:"mode"`
	UpdatedAt     time.Time  `json:"updated_at"`
	TotalRequests int64      `json:"total_requests"`
	Successful    int64      `json:"successful_requests"`
	Forbidden     int64      `json:"forbidden_requests"`
	Failures      int64      `json:"failed_requests"`
	LastPath      string     `json:"last_path,omitempty"`
	LastStatus    int        `json:"last_status,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
	LastRequestAt *time.Time `json:"last_request_at,omitempty"`
}

// Controller stores the active mode and request statistics.
type Controller struct {
	mu       sync.RWMutex
	snapshot Snapshot
	changed  chan struct{}
}

// NewController creates a Report Client controller.
func NewController(initial Mode) (*Controller, error) {
	if !IsSupportedMode(initial) {
		return nil, fmt.Errorf("unsupported report-client mode %q", initial)
	}

	return &Controller{
		snapshot: Snapshot{
			Mode:      initial,
			UpdatedAt: time.Now().UTC(),
		},
		changed: make(chan struct{}, 1),
	}, nil
}

// ParseMode converts user input into a supported mode.
func ParseMode(value string) (Mode, error) {
	mode := Mode(strings.ToLower(strings.TrimSpace(value)))
	if !IsSupportedMode(mode) {
		return "", fmt.Errorf(
			"unsupported mode %q; use normal, attack, rapid, or paused",
			value,
		)
	}

	return mode, nil
}

// IsSupportedMode reports whether a mode is valid.
func IsSupportedMode(mode Mode) bool {
	switch mode {
	case ModeNormal, ModeAttack, ModeRapid, ModePaused:
		return true
	default:
		return false
	}
}

// SetMode changes the Report Client behavior.
func (c *Controller) SetMode(mode Mode) error {
	if c == nil {
		return errors.New("report-client controller must not be nil")
	}

	if !IsSupportedMode(mode) {
		return fmt.Errorf("unsupported report-client mode %q", mode)
	}

	c.mu.Lock()
	changed := c.snapshot.Mode != mode
	c.snapshot.Mode = mode
	c.snapshot.UpdatedAt = time.Now().UTC()
	c.mu.Unlock()

	if changed {
		select {
		case c.changed <- struct{}{}:
		default:
		}
	}

	return nil
}

// Mode returns the currently active mode.
func (c *Controller) Mode() Mode {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.snapshot.Mode
}

// Snapshot returns a safe copy of the current state.
func (c *Controller) Snapshot() Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()

	copy := c.snapshot
	if c.snapshot.LastRequestAt != nil {
		value := *c.snapshot.LastRequestAt
		copy.LastRequestAt = &value
	}

	return copy
}

// Changed is signalled whenever the mode changes.
func (c *Controller) Changed() <-chan struct{} {
	return c.changed
}

// ResetStats clears runtime request counters while preserving the current mode.
func (c *Controller) ResetStats() Snapshot {
	if c == nil {
		return Snapshot{}
	}

	c.mu.Lock()
	c.snapshot.TotalRequests = 0
	c.snapshot.Successful = 0
	c.snapshot.Forbidden = 0
	c.snapshot.Failures = 0
	c.snapshot.LastPath = ""
	c.snapshot.LastStatus = 0
	c.snapshot.LastError = ""
	c.snapshot.LastRequestAt = nil
	c.snapshot.UpdatedAt = time.Now().UTC()
	snapshot := c.snapshot
	c.mu.Unlock()

	return snapshot
}

// RecordResponse updates request counters after an HTTP response.
func (c *Controller) RecordResponse(
	path string,
	status int,
	occurredAt time.Time,
) {
	c.mu.Lock()
	defer c.mu.Unlock()

	occurredAt = occurredAt.UTC()
	c.snapshot.TotalRequests++
	c.snapshot.LastPath = path
	c.snapshot.LastStatus = status
	c.snapshot.LastError = ""
	c.snapshot.LastRequestAt = &occurredAt

	switch {
	case status >= 200 && status < 300:
		c.snapshot.Successful++
	case status == 403:
		c.snapshot.Forbidden++
	default:
		c.snapshot.Failures++
	}
}

// RecordError updates request counters after a transport failure.
func (c *Controller) RecordError(
	path string,
	err error,
	occurredAt time.Time,
) {
	c.mu.Lock()
	defer c.mu.Unlock()

	occurredAt = occurredAt.UTC()
	c.snapshot.TotalRequests++
	c.snapshot.Failures++
	c.snapshot.LastPath = path
	c.snapshot.LastStatus = 0
	c.snapshot.LastRequestAt = &occurredAt

	if err != nil {
		c.snapshot.LastError = err.Error()
	} else {
		c.snapshot.LastError = "unknown request error"
	}
}
