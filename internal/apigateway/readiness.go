package apigateway

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ReadinessDependency associates a readable name with one checker.
type ReadinessDependency struct {
	Name    string
	Checker ReadinessChecker
}

// CompositeReadinessChecker requires every configured dependency to pass.
type CompositeReadinessChecker struct {
	dependencies []ReadinessDependency
}

// NewCompositeReadinessChecker creates a combined readiness checker.
func NewCompositeReadinessChecker(
	dependencies ...ReadinessDependency,
) (*CompositeReadinessChecker, error) {
	if len(dependencies) == 0 {
		return nil, errors.New(
			"at least one readiness dependency is required",
		)
	}

	stored := make(
		[]ReadinessDependency,
		0,
		len(dependencies),
	)

	for index, dependency := range dependencies {
		dependency.Name = strings.TrimSpace(dependency.Name)

		if dependency.Name == "" {
			return nil, fmt.Errorf(
				"readiness dependency %d must have a name",
				index,
			)
		}

		if dependency.Checker == nil {
			return nil, fmt.Errorf(
				"readiness dependency %q must have a checker",
				dependency.Name,
			)
		}

		stored = append(stored, dependency)
	}

	return &CompositeReadinessChecker{
		dependencies: stored,
	}, nil
}

// Check reports ready only when every dependency succeeds.
func (c *CompositeReadinessChecker) Check(
	ctx context.Context,
) error {
	if ctx == nil {
		return errors.New("context must not be nil")
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context is not usable: %w", err)
	}

	if c == nil || len(c.dependencies) == 0 {
		return errors.New(
			"composite readiness checker is not configured",
		)
	}

	for _, dependency := range c.dependencies {
		if err := dependency.Checker.Check(ctx); err != nil {
			return fmt.Errorf(
				"%s readiness check: %w",
				dependency.Name,
				err,
			)
		}
	}

	return nil
}
