package containgo.authz

import rego.v1

default allow := false

allow if {
  not input.quarantined
  input.workload == "order-client"
  input.spiffe_id == "spiffe://containgo.local/ns/containgo/sa/order-client"
  order_route
}

allow if {
  not input.quarantined
  input.workload == "report-client"
  input.spiffe_id == "spiffe://containgo.local/ns/containgo/sa/report-client"
  report_route
}

order_route if {
  input.method == "GET"
  input.path == "/api/orders"
}

order_route if {
  input.method == "POST"
  input.path == "/api/orders"
}

order_route if {
  input.method == "PUT"
  input.path == "/api/orders/ORD-1001"
}

order_route if {
  input.method == "DELETE"
  input.path == "/api/orders/ORD-1001"
}

report_route if {
  input.method == "GET"
  input.path == "/api/reports"
}

report_route if {
  input.method == "POST"
  input.path == "/api/reports/generate"
}

report_route if {
  input.method == "GET"
  input.path == "/api/customers"
}
