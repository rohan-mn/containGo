package protectedapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"containgo.local/containgo/internal/domain"
)

// GatewayAuthorizer allows only the authenticated API Gateway to invoke the
// internal Protected API. End-user authorization happens at the Gateway.
type GatewayAuthorizer struct{}

// Authorize applies the internal service-to-service boundary.
func (GatewayAuthorizer) Authorize(
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

	input.SPIFFEID = strings.TrimSpace(input.SPIFFEID)
	input.Method = strings.ToUpper(strings.TrimSpace(input.Method))
	input.Path = strings.TrimSpace(input.Path)

	if input.SPIFFEID != domain.SPIFFEIDAPIGateway {
		return AuthorizationDecision{
			Allowed: false,
			Reason:  "only the API Gateway may call the Protected API",
		}, nil
	}

	if input.Method != http.MethodGet {
		return AuthorizationDecision{
			Allowed: false,
			Reason:  "HTTP method is not permitted",
		}, nil
	}

	switch input.Path {
	case "/api/orders",
		"/api/reports",
		"/api/customers",
		"/api/payment-details",
		"/api/admin/config":
		return AuthorizationDecision{
			Allowed: true,
			Reason:  "authenticated API Gateway",
		}, nil
	default:
		return AuthorizationDecision{
			Allowed: false,
			Reason:  "unknown protected endpoint",
		}, nil
	}
}
