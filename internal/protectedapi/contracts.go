package protectedapi

import (
	"context"
	"errors"
	"net/http"
)

// ErrUnauthenticated indicates that a verified workload identity was not
// available on the request.
var ErrUnauthenticated = errors.New(
	"workload is not authenticated",
)

// IdentityResolver extracts and validates a workload identity from a request.
type IdentityResolver interface {
	Resolve(
		request *http.Request,
	) (string, error)
}

// AuthorizationInput contains the fields used to authorize one request.
type AuthorizationInput struct {
	SPIFFEID string
	Method   string
	Path     string
}

// AuthorizationDecision is the result of an authorization check.
type AuthorizationDecision struct {
	Allowed bool
	Reason  string
}

// Authorizer decides whether a workload can access an endpoint.
type Authorizer interface {
	Authorize(
		ctx context.Context,
		input AuthorizationInput,
	) (AuthorizationDecision, error)
}

// ReadinessChecker verifies whether the service dependencies are ready.
type ReadinessChecker interface {
	Check(
		ctx context.Context,
	) error
}
