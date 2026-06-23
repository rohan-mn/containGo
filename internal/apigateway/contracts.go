package apigateway

import (
	"context"
	"net/http"
	"time"

	"containgo.local/containgo/internal/controlplane"
	"containgo.local/containgo/internal/domain"
	"containgo.local/containgo/internal/protectedapi"
)

// ErrUnauthenticated indicates that a verified workload identity was not
// available on the incoming request.
var ErrUnauthenticated = protectedapi.ErrUnauthenticated

// IdentityResolver extracts a verified peer SPIFFE ID from an HTTP request.
type IdentityResolver interface {
	Resolve(request *http.Request) (string, error)
}

// Authorizer evaluates endpoint access through the policy engine.
type Authorizer interface {
	Authorize(
		ctx context.Context,
		input protectedapi.AuthorizationInput,
	) (protectedapi.AuthorizationDecision, error)
}

// EventSink sends trusted gateway observations to the control plane.
type EventSink interface {
	Check(ctx context.Context) error

	SendEvent(
		ctx context.Context,
		event domain.SecurityEvent,
	) (controlplane.IngestResult, error)
}

// QuarantineManager manages the runtime deny set used by OPA.
type QuarantineManager interface {
	Check(ctx context.Context) error

	SetQuarantined(
		ctx context.Context,
		spiffeID string,
		quarantined bool,
	) error

	ReplaceQuarantined(
		ctx context.Context,
		spiffeIDs []string,
	) error

	ListQuarantined(
		ctx context.Context,
	) ([]string, error)
}

// ReadinessChecker verifies one runtime dependency.
type ReadinessChecker interface {
	Check(ctx context.Context) error
}

// Clock provides timestamps for trusted security events.
type Clock interface {
	Now() time.Time
}
