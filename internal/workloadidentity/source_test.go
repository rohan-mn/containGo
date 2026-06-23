package workloadidentity

import (
	"crypto/x509"
	"net/url"
	"strings"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

func TestPeerID(t *testing.T) {
	id, err := spiffeid.FromString(
		"spiffe://containgo.local/ns/containgo/sa/report-client",
	)
	if err != nil {
		t.Fatalf("parse test SPIFFE ID: %v", err)
	}

	certificate := &x509.Certificate{
		URIs: []*url.URL{id.URL()},
	}

	got, err := PeerID(certificate)
	if err != nil {
		t.Fatalf("PeerID() unexpected error: %v", err)
	}

	if got != id.String() {
		t.Fatalf("PeerID() = %q, want %q", got, id)
	}
}

func TestPeerIDRejectsMissingCertificate(t *testing.T) {
	_, err := PeerID(nil)
	if err == nil || !strings.Contains(err.Error(), "must not be nil") {
		t.Fatalf("PeerID(nil) error = %v", err)
	}
}

func TestPeerIDRejectsCertificateWithoutSPIFFEID(t *testing.T) {
	_, err := PeerID(&x509.Certificate{})
	if err == nil || !strings.Contains(err.Error(), "extract SPIFFE ID") {
		t.Fatalf("PeerID() error = %v", err)
	}
}

func TestParseIDsRejectsInvalidIdentity(t *testing.T) {
	_, err := parseIDs([]string{"not-a-spiffe-id"})
	if err == nil || !strings.Contains(err.Error(), "parse allowed client SPIFFE ID 0") {
		t.Fatalf("parseIDs() error = %v", err)
	}
}
