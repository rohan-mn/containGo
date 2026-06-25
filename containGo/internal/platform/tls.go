package platform

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type IdentityFiles struct {
	CertFile   string
	KeyFile    string
	BundleFile string
}

func DefaultIdentityFiles() IdentityFiles {
	return IdentityFiles{
		CertFile:   envOr("SPIFFE_CERT_FILE", "/run/spiffe/certs/svid.pem"),
		KeyFile:    envOr("SPIFFE_KEY_FILE", "/run/spiffe/certs/svid_key.pem"),
		BundleFile: envOr("SPIFFE_BUNDLE_FILE", "/run/spiffe/certs/bundle.pem"),
	}
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func LoadIdentityInfo(files IdentityFiles, workload string) (IdentityInfo, error) {
	certPEM, err := os.ReadFile(files.CertFile)
	if err != nil {
		return IdentityInfo{}, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return IdentityInfo{}, errors.New("SVID certificate is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return IdentityInfo{}, err
	}
	return IdentityInfo{
		Workload:       workload,
		SPIFFEID:       CertificateSPIFFEID(cert),
		SerialNumber:   cert.SerialNumber.Text(16),
		NotBefore:      cert.NotBefore.UTC(),
		NotAfter:       cert.NotAfter.UTC(),
		Issuer:         cert.Issuer.String(),
		Subject:        cert.Subject.String(),
		DNSNames:       append([]string(nil), cert.DNSNames...),
		CertificatePEM: string(certPEM),
	}, nil
}

func CertificateSPIFFEID(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	for _, uri := range cert.URIs {
		if uri != nil && uri.Scheme == "spiffe" {
			return uri.String()
		}
	}
	return ""
}

func ReadyIdentity(files IdentityFiles) error {
	info, err := LoadIdentityInfo(files, "")
	if err != nil {
		return fmt.Errorf("SPIFFE SVID is not ready: %w", err)
	}
	if info.SPIFFEID == "" {
		return errors.New("SPIFFE SVID has no URI SAN")
	}
	if time.Until(info.NotAfter) <= 0 {
		return errors.New("SPIFFE SVID has expired")
	}
	return nil
}

func DynamicServerTLS(files IdentityFiles, allowPeer func(string) bool) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAnyClientCert,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			certificate, err := tls.LoadX509KeyPair(files.CertFile, files.KeyFile)
			if err != nil {
				return nil, err
			}
			return &certificate, nil
		},
		VerifyConnection: func(state tls.ConnectionState) error {
			return verifyConnection(files, state, x509.ExtKeyUsageClientAuth, "", allowPeer)
		},
	}
}

func DynamicClientTLS(files IdentityFiles, expectedPeer string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // Verification is performed below against the SPIFFE bundle and URI SAN.
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			certificate, err := tls.LoadX509KeyPair(files.CertFile, files.KeyFile)
			if err != nil {
				return nil, err
			}
			return &certificate, nil
		},
		VerifyConnection: func(state tls.ConnectionState) error {
			return verifyConnection(files, state, x509.ExtKeyUsageServerAuth, expectedPeer, nil)
		},
	}
}

func verifyConnection(files IdentityFiles, state tls.ConnectionState, usage x509.ExtKeyUsage, expectedPeer string, allowPeer func(string) bool) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New("peer did not provide an X.509-SVID")
	}
	roots, err := loadBundle(files.BundleFile)
	if err != nil {
		return err
	}
	leaf := state.PeerCertificates[0]
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{usage},
		CurrentTime:   time.Now(),
	}); err != nil {
		return fmt.Errorf("peer X.509-SVID verification failed: %w", err)
	}
	peerID := CertificateSPIFFEID(leaf)
	if peerID == "" {
		return errors.New("peer certificate has no SPIFFE URI SAN")
	}
	if expectedPeer != "" && peerID != expectedPeer {
		return fmt.Errorf("unexpected peer SPIFFE ID %q; expected %q", peerID, expectedPeer)
	}
	if allowPeer != nil && !allowPeer(peerID) {
		return fmt.Errorf("peer SPIFFE ID %q is not allowed", peerID)
	}
	return nil
}

var bundleCache struct {
	sync.Mutex
	path    string
	modTime time.Time
	pool    *x509.CertPool
}

func loadBundle(path string) (*x509.CertPool, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read SPIFFE bundle: %w", err)
	}
	bundleCache.Lock()
	defer bundleCache.Unlock()
	if bundleCache.pool != nil && bundleCache.path == path && bundleCache.modTime.Equal(stat.ModTime()) {
		return bundleCache.pool, nil
	}
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("SPIFFE bundle does not contain a valid certificate")
	}
	bundleCache.path = path
	bundleCache.modTime = stat.ModTime()
	bundleCache.pool = pool
	return pool, nil
}

func MTLSHTTPClient(files IdentityFiles, expectedPeer string, timeout time.Duration) *httpClientWrapper {
	return newHTTPClientWrapper(files, expectedPeer, timeout)
}
