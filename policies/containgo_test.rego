package containgo.authz_test

import data.containgo.authz.decision

order_client := "spiffe://containgo.local/ns/containgo/sa/order-client"
report_client := "spiffe://containgo.local/ns/containgo/sa/report-client"

empty_quarantine := {}

test_order_client_can_read_orders if {
	result := decision with input as {
		"spiffe_id": order_client,
		"method": "GET",
		"path": "/api/orders",
	} with data.containgo.quarantined as empty_quarantine
	result.allowed == true
}

test_order_client_cannot_read_reports if {
	result := decision with input as {
		"spiffe_id": order_client,
		"method": "GET",
		"path": "/api/reports",
	} with data.containgo.quarantined as empty_quarantine
	result.allowed == false
}

test_report_client_can_read_reports if {
	result := decision with input as {
		"spiffe_id": report_client,
		"method": "GET",
		"path": "/api/reports",
	} with data.containgo.quarantined as empty_quarantine
	result.allowed == true
}

test_report_client_cannot_read_sensitive_endpoint if {
	result := decision with input as {
		"spiffe_id": report_client,
		"method": "GET",
		"path": "/api/payment-details",
	} with data.containgo.quarantined as empty_quarantine
	result.allowed == false
}

test_non_get_method_is_denied if {
	result := decision with input as {
		"spiffe_id": report_client,
		"method": "POST",
		"path": "/api/reports",
	} with data.containgo.quarantined as empty_quarantine
	result.allowed == false
}

test_quarantine_overrides_allowed_route if {
	result := decision with input as {
		"spiffe_id": report_client,
		"method": "GET",
		"path": "/api/reports",
	} with data.containgo.quarantined as {
		"spiffe://containgo.local/ns/containgo/sa/report-client": true,
	}
	result.allowed == false
	result.reason == "workload is quarantined"
}
