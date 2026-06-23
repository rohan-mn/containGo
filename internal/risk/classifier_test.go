package risk

import (
	"net/http"
	"testing"

	"containgo.local/containgo/internal/domain"
)

func TestClassifyEndpoint(t *testing.T) {
	tests := []struct {
		name string
		path string
		want EndpointSensitivity
	}{
		{
			name: "orders is standard",
			path: "/api/orders",
			want: EndpointStandard,
		},
		{
			name: "reports is standard",
			path: "/api/reports",
			want: EndpointStandard,
		},
		{
			name: "customers is sensitive",
			path: "/api/customers",
			want: EndpointSensitive,
		},
		{
			name: "admin config is administrative",
			path: "/api/admin/config",
			want: EndpointAdministrative,
		},
		{
			name: "payment details is highly sensitive",
			path: "/api/payment-details",
			want: EndpointHighlySensitive,
		},
		{
			name: "unknown path is standard",
			path: "/api/unknown",
			want: EndpointStandard,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyEndpoint(tt.path)

			if got != tt.want {
				t.Fatalf(
					"ClassifyEndpoint(%q) = %q, want %q",
					tt.path,
					got,
					tt.want,
				)
			}
		})
	}
}

func TestSensitivityRiskRule(t *testing.T) {
	tests := []struct {
		name      string
		class     EndpointSensitivity
		wantRule  domain.RiskRule
		wantFound bool
	}{
		{
			name:      "standard has no risk rule",
			class:     EndpointStandard,
			wantFound: false,
		},
		{
			name:      "sensitive endpoint",
			class:     EndpointSensitive,
			wantRule:  domain.RiskRuleSensitiveEndpoint,
			wantFound: true,
		},
		{
			name:      "administrative endpoint",
			class:     EndpointAdministrative,
			wantRule:  domain.RiskRuleAdministrative,
			wantFound: true,
		},
		{
			name:      "highly sensitive endpoint",
			class:     EndpointHighlySensitive,
			wantRule:  domain.RiskRuleHighlySensitive,
			wantFound: true,
		},
		{
			name:      "unknown classification",
			class:     EndpointSensitivity("unknown"),
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRule, gotFound := SensitivityRiskRule(tt.class)

			if gotFound != tt.wantFound {
				t.Fatalf(
					"SensitivityRiskRule(%q) found = %t, want %t",
					tt.class,
					gotFound,
					tt.wantFound,
				)
			}

			if gotRule != tt.wantRule {
				t.Fatalf(
					"SensitivityRiskRule(%q) rule = %q, want %q",
					tt.class,
					gotRule,
					tt.wantRule,
				)
			}
		})
	}
}

func TestIsAuthorizedRequest(t *testing.T) {
	tests := []struct {
		name       string
		workloadID string
		method     string
		path       string
		want       bool
	}{
		{
			name:       "order client can access orders",
			workloadID: domain.SPIFFEIDOrderClient,
			method:     http.MethodGet,
			path:       "/api/orders",
			want:       true,
		},
		{
			name:       "order client cannot access reports",
			workloadID: domain.SPIFFEIDOrderClient,
			method:     http.MethodGet,
			path:       "/api/reports",
			want:       false,
		},
		{
			name:       "report client can access reports",
			workloadID: domain.SPIFFEIDReportClient,
			method:     http.MethodGet,
			path:       "/api/reports",
			want:       true,
		},
		{
			name:       "report client cannot access orders",
			workloadID: domain.SPIFFEIDReportClient,
			method:     http.MethodGet,
			path:       "/api/orders",
			want:       false,
		},
		{
			name:       "report client cannot access customers",
			workloadID: domain.SPIFFEIDReportClient,
			method:     http.MethodGet,
			path:       "/api/customers",
			want:       false,
		},
		{
			name:       "post method is rejected",
			workloadID: domain.SPIFFEIDReportClient,
			method:     http.MethodPost,
			path:       "/api/reports",
			want:       false,
		},
		{
			name: "unknown identity is rejected",
			workloadID: "spiffe://containgo.local/" +
				"ns/containgo/sa/unknown",
			method: http.MethodGet,
			path:   "/api/orders",
			want:   false,
		},
		{
			name:       "internal workload is rejected",
			workloadID: domain.SPIFFEIDControlPlane,
			method:     http.MethodGet,
			path:       "/api/orders",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsAuthorizedRequest(
				tt.workloadID,
				tt.method,
				tt.path,
			)

			if got != tt.want {
				t.Fatalf(
					"IsAuthorizedRequest(%q, %q, %q) = %t, want %t",
					tt.workloadID,
					tt.method,
					tt.path,
					got,
					tt.want,
				)
			}
		})
	}
}
