# ContainGo Architecture

## Identity-preserving request flow

1. The browser sends a normal localhost request to the Dashboard.
2. The Dashboard uses its X.509-SVID to establish mTLS with the selected client control API.
3. The client validates that the peer is Dashboard.
4. The client reads its current SVID files, which SPIFFE Helper continuously refreshes from the local SPIRE Agent Workload API.
5. The client establishes TLS 1.3 mutual authentication with the API Gateway.
6. The Gateway derives the caller from the peer certificate URI SAN. No caller identity header is trusted.
7. The Gateway retrieves the caller's current quarantine state from the Control Plane.
8. The Gateway asks its localhost OPA sidecar to evaluate SPIFFE ID, workload, HTTP method, route, and quarantine state.
9. For an allowed request, the Gateway creates a separate mTLS connection to Protected API using the Gateway SVID.
10. Protected API accepts business endpoints only when the peer identity is the API Gateway.
11. The Gateway sends a correlated decision event to the Control Plane over another Gateway-authenticated mTLS connection.
12. The Control Plane calculates risk, persists evidence, and creates an incident when the threshold is crossed.
13. The Dashboard receives evidence through Server-Sent Events and animates the real edges.

## Why the Dashboard does not directly call the Gateway as a client

An mTLS peer identity comes from the private key and certificate used in the TLS handshake. A browser dropdown cannot safely change that identity. If Dashboard called Gateway directly, Gateway would correctly see the Dashboard SPIFFE ID. The client control API preserves the security model by ensuring that Order Client or Report Client creates the business connection itself.

## Containers and pods

Each application Deployment contains:

- One Go application container.
- One SPIFFE Helper sidecar that reads the SPIRE Agent Unix socket and writes rotating SVID files to a shared `emptyDir`.

API Gateway additionally contains an OPA sidecar. SPIRE Agent runs as a privileged DaemonSet on the kind node and exposes the Workload API through a host-mounted Unix socket.

## Network boundaries

Calico enforces default-deny policies. The intended network edges are:

- Dashboard → Order Client control API.
- Dashboard → Report Client control API.
- Dashboard → component identity/administration APIs.
- Order Client → API Gateway.
- Report Client → API Gateway.
- API Gateway → Protected API.
- API Gateway → Control Plane.

Direct client access to Protected API is not allowed by NetworkPolicy and would also fail the Protected API SPIFFE authorization check.
