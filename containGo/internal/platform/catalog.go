package platform

import (
	"sort"
	"strings"
)

var endpointCatalog = []Endpoint{
	{Method: "GET", Path: "/api/orders", Description: "List orders", AllowedFor: []string{"order-client"}},
	{Method: "POST", Path: "/api/orders", Description: "Create an order", AllowedFor: []string{"order-client"}},
	{Method: "PUT", Path: "/api/orders/ORD-1001", Description: "Update an order", AllowedFor: []string{"order-client"}},
	{Method: "DELETE", Path: "/api/orders/ORD-1001", Description: "Delete an order", AllowedFor: []string{"order-client"}},
	{Method: "GET", Path: "/api/reports", Description: "List reports", AllowedFor: []string{"report-client"}},
	{Method: "POST", Path: "/api/reports/generate", Description: "Generate a report", AllowedFor: []string{"report-client"}},
	{Method: "GET", Path: "/api/customers", Description: "List customer summaries", AllowedFor: []string{"report-client"}},
	{Method: "GET", Path: "/api/payment-details", Description: "Read sensitive payment details", AllowedFor: nil, RiskLabel: "highly_sensitive_endpoint_attempt"},
	{Method: "PUT", Path: "/api/admin/config", Description: "Change protected administrative configuration", AllowedFor: nil, RiskLabel: "administrative_endpoint_attempt"},
	{Method: "POST", Path: "/api/admin/config", Description: "Create protected administrative configuration", AllowedFor: nil, RiskLabel: "administrative_endpoint_attempt"},
}

func EndpointCatalog() []Endpoint {
	out := make([]Endpoint, len(endpointCatalog))
	copy(out, endpointCatalog)
	return out
}

func CatalogForWorkload(workload string) []Endpoint {
	out := EndpointCatalog()
	sort.Slice(out, func(i, j int) bool {
		iAllowed := contains(out[i].AllowedFor, workload)
		jAllowed := contains(out[j].AllowedFor, workload)
		if iAllowed != jAllowed {
			return iAllowed
		}
		if out[i].Path == out[j].Path {
			return out[i].Method < out[j].Method
		}
		return out[i].Path < out[j].Path
	})
	return out
}

func IsKnownEndpoint(method, path string) bool {
	method = strings.ToUpper(strings.TrimSpace(method))
	for _, endpoint := range endpointCatalog {
		if endpoint.Method == method && endpoint.Path == path {
			return true
		}
	}
	return false
}

func IsAllowed(workload, method, path string) bool {
	method = strings.ToUpper(strings.TrimSpace(method))
	for _, endpoint := range endpointCatalog {
		if endpoint.Method == method && endpoint.Path == path {
			return contains(endpoint.AllowedFor, workload)
		}
	}
	return false
}

func WorkloadFromSPIFFEID(id string) string {
	if idx := strings.LastIndex(id, "/"); idx >= 0 && idx+1 < len(id) {
		return id[idx+1:]
	}
	return id
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
