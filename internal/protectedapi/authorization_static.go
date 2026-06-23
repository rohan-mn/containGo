package protectedapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"containgo.local/containgo/internal/domain"
)

// StaticAuthorizer is the temporary Phase 3 authorization implementation.
//
// Phase 4 will replace this implementation with an OPA client.
type StaticAuthorizer struct{}

// Authorize applies the initial endpoint-access rules.
func (StaticAuthorizer) Authorize(
	ctx context.Context,
	input AuthorizationInput,
) (AuthorizationDecision, error) {
	if ctx == nil {
		return AuthorizationDecision{}, errors.New(
			"context must not be nil",
		)
	}

	if err := ctx.Err(); err != nil {
		return AuthorizationDecision{}, fmt.Errorf(
			"context is not usable: %w",
			err,
		)
	}

	input.SPIFFEID = strings.TrimSpace(
		input.SPIFFEID,
	)
	input.Method = strings.ToUpper(
		strings.TrimSpace(input.Method),
	)
	input.Path = strings.TrimSpace(
		input.Path,
	)

	if !domain.IsKnownWorkloadID(input.SPIFFEID) {
		return AuthorizationDecision{
			Allowed: false,
			Reason:  "unknown workload identity",
		}, nil
	}

	if input.Method != http.MethodGet {
		return AuthorizationDecision{
			Allowed: false,
			Reason:  "HTTP method is not permitted",
		}, nil
	}

	var allowedPath string

	switch input.SPIFFEID {
	case domain.SPIFFEIDOrderClient:
		allowedPath = "/api/orders"

	case domain.SPIFFEIDReportClient:
		allowedPath = "/api/reports"
	}

	if allowedPath == "" {
		return AuthorizationDecision{
			Allowed: false,
			Reason:  "workload has no protected API permissions",
		}, nil
	}

	if input.Path != allowedPath {
		return AuthorizationDecision{
			Allowed: false,
			Reason:  "workload is not permitted to access this endpoint",
		}, nil
	}

	return AuthorizationDecision{
		Allowed: true,
		Reason:  "static Phase 3 policy allowed the request",
	}, nil
}
