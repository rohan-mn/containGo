package containgo.authz

# The default result is always deny.
default decision := {
	"allowed": false,
	"reason": "workload is not permitted to access this endpoint",
}

# Phase 4 endpoint permissions.
#
# Additional workloads and routes can be added later without changing
# the protected API binary.
allowed_paths := {
	"spiffe://containgo.local/ns/containgo/sa/order-client": "/api/orders",
	"spiffe://containgo.local/ns/containgo/sa/report-client": "/api/reports",
}

# A workload is quarantined when the runtime OPA data document contains:
#
# data.containgo.quarantined[spiffe_id] == true
quarantined if {
	data.containgo.quarantined[input.spiffe_id] == true
}

# A route is allowed only when:
#
# - the HTTP method is GET
# - the workload is present in allowed_paths
# - the requested path exactly matches its configured route
route_allowed if {
	input.method == "GET"
	allowed_paths[input.spiffe_id] == input.path
}

# Quarantine overrides every normal route permission.
decision := {
	"allowed": false,
	"reason": "workload is quarantined",
} if {
	quarantined
}

# A non-quarantined workload may access only its assigned route.
decision := {
	"allowed": true,
	"reason": "OPA policy allowed the request",
} if {
	not quarantined
	route_allowed
}