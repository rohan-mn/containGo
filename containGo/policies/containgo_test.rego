package containgo.authz_test

import rego.v1
import data.containgo.authz

test_order_read_allowed if {
  authz.allow with input as {
    "spiffe_id": "spiffe://containgo.local/ns/containgo/sa/order-client",
    "workload": "order-client",
    "method": "GET",
    "path": "/api/orders",
    "quarantined": false,
  }
}

test_report_cannot_read_payments if {
  not authz.allow with input as {
    "spiffe_id": "spiffe://containgo.local/ns/containgo/sa/report-client",
    "workload": "report-client",
    "method": "GET",
    "path": "/api/payment-details",
    "quarantined": false,
  }
}

test_quarantined_order_denied if {
  not authz.allow with input as {
    "spiffe_id": "spiffe://containgo.local/ns/containgo/sa/order-client",
    "workload": "order-client",
    "method": "GET",
    "path": "/api/orders",
    "quarantined": true,
  }
}
