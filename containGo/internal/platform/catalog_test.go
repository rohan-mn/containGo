package platform

import "testing"

func TestCatalogAuthorization(t *testing.T) {
	if !IsAllowed("order-client", "GET", "/api/orders") {
		t.Fatal("order client should be allowed to list orders")
	}
	if IsAllowed("report-client", "GET", "/api/payment-details") {
		t.Fatal("report client must not be allowed to read payment details")
	}
	if !IsKnownEndpoint("PUT", "/api/admin/config") {
		t.Fatal("administrative endpoint should remain visible in the endpoint catalogue")
	}
}
