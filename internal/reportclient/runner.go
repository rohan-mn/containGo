package reportclient

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"containgo.local/containgo/internal/workloadclient"
)

// RunnerConfig controls Report Client request timing.
type RunnerConfig struct {
	NormalInterval time.Duration
	AttackInterval time.Duration
	RapidInterval  time.Duration
	RapidBurst     int
}

// Runner executes the behavior associated with the active Report Client mode.
type Runner struct {
	client     *workloadclient.Client
	controller *Controller
	config     RunnerConfig
}

// NewRunner creates a mode-aware Report Client runner.
func NewRunner(
	client *workloadclient.Client,
	controller *Controller,
	config RunnerConfig,
) (*Runner, error) {
	if client == nil {
		return nil, errors.New("workload HTTP client must not be nil")
	}

	if controller == nil {
		return nil, errors.New("report-client controller must not be nil")
	}

	if config.NormalInterval <= 0 {
		config.NormalInterval = 5 * time.Second
	}
	if config.AttackInterval <= 0 {
		config.AttackInterval = 3 * time.Second
	}
	if config.RapidInterval <= 0 {
		config.RapidInterval = 15 * time.Second
	}
	if config.RapidBurst <= 30 {
		config.RapidBurst = 35
	}

	return &Runner{
		client:     client,
		controller: controller,
		config:     config,
	}, nil
}

// Run executes requests until the context is cancelled.
func (r *Runner) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("context must not be nil")
	}

	for {
		if err := ctx.Err(); err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return fmt.Errorf("report-client context: %w", err)
		}

		mode := r.controller.Mode()
		waitDuration := r.config.NormalInterval

		switch mode {
		case ModeNormal:
			r.request(ctx, "/api/reports")
			waitDuration = r.config.NormalInterval

		case ModeAttack:
			r.request(ctx, "/api/payment-details")
			if ctx.Err() == nil {
				r.request(ctx, "/api/admin/config")
			}
			waitDuration = r.config.AttackInterval

		case ModeRapid:
			for count := 0; count < r.config.RapidBurst; count++ {
				if ctx.Err() != nil || r.controller.Mode() != ModeRapid {
					break
				}
				r.request(ctx, "/api/reports")
			}
			waitDuration = r.config.RapidInterval

		case ModePaused:
			waitDuration = 24 * time.Hour

		default:
			return fmt.Errorf("unsupported report-client mode %q", mode)
		}

		if !r.wait(ctx, waitDuration) {
			return nil
		}
	}
}

func (r *Runner) request(
	ctx context.Context,
	path string,
) {
	response, err := r.client.Get(ctx, path)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}

		r.controller.RecordError(
			path,
			err,
			time.Now().UTC(),
		)
		log.Printf("report-client GET %s failed: %v", path, err)
		return
	}

	r.controller.RecordResponse(
		path,
		response.StatusCode,
		response.ReceivedAt,
	)

	message := strings.TrimSpace(string(response.Body))
	if len(message) > 240 {
		message = message[:240] + "..."
	}

	if response.Successful() {
		log.Printf(
			"report-client mode=%s GET %s -> %d",
			r.controller.Mode(),
			path,
			response.StatusCode,
		)
		return
	}

	log.Printf(
		"report-client mode=%s GET %s -> %d %s",
		r.controller.Mode(),
		path,
		response.StatusCode,
		message,
	)
}

func (r *Runner) wait(
	ctx context.Context,
	duration time.Duration,
) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-r.controller.Changed():
		return true
	case <-timer.C:
		return true
	}
}
