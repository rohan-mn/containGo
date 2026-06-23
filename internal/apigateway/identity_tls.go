package apigateway

import (
	"fmt"
	"net/http"

	"containgo.local/containgo/internal/domain"
	"containgo.local/containgo/internal/workloadidentity"
)

// TLSIdentityResolver extracts one exact, known SPIFFE identity from a peer
// certificate already authenticated by the SPIFFE TLS configuration.
type TLSIdentityResolver struct{}

// Resolve returns the authenticated peer SPIFFE ID.
func (TLSIdentityResolver) Resolve(
	request *http.Request,
) (string, error) {
	if request == nil {
		return "", fmt.Errorf(
			"%w: request must not be nil",
			ErrUnauthenticated,
		)
	}

	if request.TLS == nil || len(request.TLS.PeerCertificates) == 0 {
		return "", fmt.Errorf(
			"%w: an authenticated X.509-SVID is required",
			ErrUnauthenticated,
		)
	}

	spiffeID, err := workloadidentity.PeerID(
		request.TLS.PeerCertificates[0],
	)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}

	if !domain.IsKnownWorkloadID(spiffeID) {
		return "", fmt.Errorf(
			"%w: unknown SPIFFE ID %q",
			ErrUnauthenticated,
			spiffeID,
		)
	}

	return spiffeID, nil
}
