package workloadidentity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// Config identifies the workload and optionally overrides the Workload API
// endpoint. When SocketAddress is empty, go-spiffe uses SPIFFE_ENDPOINT_SOCKET.
type Config struct {
	ExpectedID    string
	SocketAddress string
}

// Source keeps the current X.509-SVID and trust bundles synchronized with the
// SPIFFE Workload API.
type Source struct {
	x509Source *workloadapi.X509Source
	expectedID spiffeid.ID
}

// IdentityInfo describes the currently active X.509-SVID.
type IdentityInfo struct {
	SPIFFEID  string
	NotBefore time.Time
	NotAfter  time.Time
	Serial    string
}

// New creates a Workload API-backed X.509 source and verifies that SPIRE
// issued the exact identity expected by this process.
func New(
	ctx context.Context,
	config Config,
) (*Source, error) {
	if ctx == nil {
		return nil, errors.New("context must not be nil")
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context is not usable: %w", err)
	}

	expectedID, err := spiffeid.FromString(
		strings.TrimSpace(config.ExpectedID),
	)
	if err != nil {
		return nil, fmt.Errorf("parse expected SPIFFE ID: %w", err)
	}

	var options []workloadapi.X509SourceOption

	if socketAddress := strings.TrimSpace(config.SocketAddress); socketAddress != "" {
		if err = workloadapi.ValidateAddress(socketAddress); err != nil {
			return nil, fmt.Errorf("validate Workload API address: %w", err)
		}

		options = append(
			options,
			workloadapi.WithClientOptions(
				workloadapi.WithAddr(socketAddress),
			),
		)
	}

	x509Source, err := workloadapi.NewX509Source(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("connect to SPIFFE Workload API: %w", err)
	}

	source := &Source{
		x509Source: x509Source,
		expectedID: expectedID,
	}

	if _, err = source.Current(); err != nil {
		_ = x509Source.Close()
		return nil, err
	}

	return source, nil
}

// Close releases the Workload API connection.
func (s *Source) Close() error {
	if s == nil || s.x509Source == nil {
		return nil
	}

	return s.x509Source.Close()
}

// Current returns information about the currently active X.509-SVID and
// rejects any unexpected identity assignment.
func (s *Source) Current() (IdentityInfo, error) {
	if s == nil || s.x509Source == nil {
		return IdentityInfo{}, errors.New("workload identity source is not configured")
	}

	svid, err := s.x509Source.GetX509SVID()
	if err != nil {
		return IdentityInfo{}, fmt.Errorf("read current X.509-SVID: %w", err)
	}

	if svid.ID != s.expectedID {
		return IdentityInfo{}, fmt.Errorf(
			"SPIRE issued unexpected identity %q, want %q",
			svid.ID,
			s.expectedID,
		)
	}

	if len(svid.Certificates) == 0 {
		return IdentityInfo{}, errors.New("X.509-SVID has no certificates")
	}

	leaf := svid.Certificates[0]

	return IdentityInfo{
		SPIFFEID:  svid.ID.String(),
		NotBefore: leaf.NotBefore.UTC(),
		NotAfter:  leaf.NotAfter.UTC(),
		Serial:    leaf.SerialNumber.String(),
	}, nil
}

// ClientTLSConfig returns an mTLS client configuration that presents this
// workload's rotating X.509-SVID and authorizes one exact server identity.
func (s *Source) ClientTLSConfig(
	expectedServerID string,
) (*tls.Config, error) {
	if s == nil || s.x509Source == nil {
		return nil, errors.New("workload identity source is not configured")
	}

	serverID, err := spiffeid.FromString(
		strings.TrimSpace(expectedServerID),
	)
	if err != nil {
		return nil, fmt.Errorf("parse expected server SPIFFE ID: %w", err)
	}

	config := tlsconfig.MTLSClientConfig(
		s.x509Source,
		s.x509Source,
		tlsconfig.AuthorizeID(serverID),
	)
	applyTLSDefaults(config)

	return config, nil
}

// ServerTLSConfig returns a SPIFFE-aware TLS server configuration.
//
// When requireClientCertificate is true, the TLS handshake requires and
// authorizes one of the listed identities. When false, anonymous health probes
// are allowed, while any client certificate that is supplied is still
// validated and restricted to the listed identities. Application handlers
// must require an authenticated peer on protected routes.
func (s *Source) ServerTLSConfig(
	requireClientCertificate bool,
	allowedClientIDs ...string,
) (*tls.Config, error) {
	if s == nil || s.x509Source == nil {
		return nil, errors.New("workload identity source is not configured")
	}

	allowed, err := parseIDs(allowedClientIDs)
	if err != nil {
		return nil, err
	}

	if len(allowed) == 0 {
		return nil, errors.New("at least one allowed client SPIFFE ID is required")
	}

	authorizer := tlsconfig.AuthorizeOneOf(allowed...)

	if requireClientCertificate {
		config := tlsconfig.MTLSServerConfig(
			s.x509Source,
			s.x509Source,
			authorizer,
		)
		applyTLSDefaults(config)
		return config, nil
	}

	config := tlsconfig.TLSServerConfig(s.x509Source)
	config.ClientAuth = tls.RequestClientCert

	verifyPeer := tlsconfig.VerifyPeerCertificate(
		s.x509Source,
		authorizer,
	)

	config.VerifyPeerCertificate = func(
		rawCerts [][]byte,
		verifiedChains [][]*x509.Certificate,
	) error {
		if len(rawCerts) == 0 {
			return nil
		}

		return verifyPeer(rawCerts, verifiedChains)
	}

	applyTLSDefaults(config)
	return config, nil
}

// PeerID extracts the SPIFFE ID from a certificate that has already been
// authenticated by the server's SPIFFE TLS configuration.
func PeerID(certificate *x509.Certificate) (string, error) {
	if certificate == nil {
		return "", errors.New("peer certificate must not be nil")
	}

	id, err := x509svid.IDFromCert(certificate)
	if err != nil {
		return "", fmt.Errorf("extract SPIFFE ID from peer certificate: %w", err)
	}

	return id.String(), nil
}

// LogUpdates writes the current SVID and every subsequent rotation event.
func (s *Source) LogUpdates(
	ctx context.Context,
	logf func(string, ...any),
) {
	if s == nil || s.x509Source == nil || ctx == nil || logf == nil {
		return
	}

	logCurrent := func(prefix string) {
		info, err := s.Current()
		if err != nil {
			logf("%s identity unavailable: %v", prefix, err)
			return
		}

		logf(
			"%s SPIFFE identity=%s serial=%s valid_until=%s",
			prefix,
			info.SPIFFEID,
			info.Serial,
			info.NotAfter.Format(time.RFC3339),
		)
	}

	logCurrent("loaded")

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-s.x509Source.Updated():
				logCurrent("rotated")
			}
		}
	}()
}

func parseIDs(values []string) ([]spiffeid.ID, error) {
	ids := make([]spiffeid.ID, 0, len(values))

	for index, value := range values {
		id, err := spiffeid.FromString(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf(
				"parse allowed client SPIFFE ID %d: %w",
				index,
				err,
			)
		}

		ids = append(ids, id)
	}

	return ids, nil
}

func applyTLSDefaults(config *tls.Config) {
	config.MinVersion = tls.VersionTLS12
	config.NextProtos = []string{
		"h2",
		"http/1.1",
	}
}
