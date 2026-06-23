package controlplane

import (
	"errors"
	"fmt"
	"net/http"

	"containgo.local/containgo/internal/domain"
	"containgo.local/containgo/internal/workloadidentity"
)

// ErrUnauthenticated indicates that a verified workload identity was not
// available on the request.
var ErrUnauthenticated = errors.New("workload is not authenticated")

// IdentityResolver extracts an authenticated SPIFFE identity from a request.
type IdentityResolver interface {
	Resolve(request *http.Request) (string, error)
}

// TLSIdentityResolver reads a SPIFFE ID from an X.509-SVID already
// authenticated by the SPIFFE TLS server configuration.
type TLSIdentityResolver struct{}

// Resolve extracts one exact known SPIFFE ID from the peer certificate.
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
			"%w: authenticated X.509-SVID is required",
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
