package risk

import (
	"net/http"
	"strings"

	"containgo.local/containgo/internal/domain"
)

// EndpointSensitivity describes the security classification of an API path.
type EndpointSensitivity string

const (
	EndpointStandard EndpointSensitivity = "standard"

	EndpointSensitive EndpointSensitivity = "sensitive"

	EndpointAdministrative EndpointSensitivity = "administrative"

	EndpointHighlySensitive EndpointSensitivity = "highly_sensitive"
)

// ClassifyEndpoint returns the security classification assigned to a path.
//
// Unknown paths are treated as standard here. They may still receive
// unauthorized-endpoint risk points when the workload is not permitted
// to access them.
func ClassifyEndpoint(path string) EndpointSensitivity {
	switch strings.TrimSpace(path) {
	case "/api/customers":
		return EndpointSensitive

	case "/api/admin/config":
		return EndpointAdministrative

	case "/api/payment-details":
		return EndpointHighlySensitive

	default:
		return EndpointStandard
	}
}

// SensitivityRiskRule maps an endpoint classification to its risk rule.
//
// Standard endpoints do not have an additional sensitivity contribution.
func SensitivityRiskRule(
	sensitivity EndpointSensitivity,
) (domain.RiskRule, bool) {
	switch sensitivity {
	case EndpointSensitive:
		return domain.RiskRuleSensitiveEndpoint, true

	case EndpointAdministrative:
		return domain.RiskRuleAdministrative, true

	case EndpointHighlySensitive:
		return domain.RiskRuleHighlySensitive, true

	default:
		return "", false
	}
}

// IsAuthorizedRequest applies ContainGo's static workload-access model.
//
// This function independently determines authorization from the authenticated
// SPIFFE ID, HTTP method, and request path. It never reads an identity header.
func IsAuthorizedRequest(
	workloadID string,
	method string,
	path string,
) bool {
	if strings.TrimSpace(method) != http.MethodGet {
		return false
	}

	switch strings.TrimSpace(workloadID) {
	case domain.SPIFFEIDOrderClient:
		return strings.TrimSpace(path) == "/api/orders"

	case domain.SPIFFEIDReportClient:
		return strings.TrimSpace(path) == "/api/reports"

	default:
		return false
	}
}
