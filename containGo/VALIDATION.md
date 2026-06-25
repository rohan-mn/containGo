# Validation Record

This V7 package was prepared and validated on June 25, 2026.

## Windows field evidence and V7 root cause

The user's V5 Windows run passed Docker, kind, Kubernetes RBAC, Calico,
CoreDNS, image loading, SPIRE Server, token-derived Agent attestation, Workload
API socket publication, and all six workload registration entries. It failed at
the application deployment stage because older Deployments contained an
additional immutable `app.kubernetes.io/name` selector. The V7 manifests use
`app=<workload>` as the selector. Kubernetes cannot modify an apps/v1
Deployment selector in place.

V7 inspects each live Deployment and recreates only those whose immutable
selector differs from the V7 selector. Services, ServiceAccounts, ConfigMaps,
SPIRE state, PVCs, and Control Plane persistent storage are not deleted.

The audit also found that the Dashboard manifest probed port 8081 even though
the Dashboard serves `/healthz` and `/readyz` on its application listener at
port 8060. V7 points both Dashboard probes at the named `app` port.

## Source and build checks passed

- `gofmt` completed successfully.
- `go test ./...` passed.
- `go test -race ./...` passed.
- `go vet ./...` passed.
- Linux/amd64 builds passed for all six commands: `api-gateway`,
  `control-plane`, `dashboard`, `order-client`, `protected-api`, and
  `report-client`.
- JavaScript syntax validation passed with `node --check`.
- Every Kubernetes YAML document parsed successfully.
- All named HTTP probe ports resolve to ports declared by the same container.
- Both Postman JSON files parsed successfully.
- The included local root certificate and private key are valid and match.
- The V7 launcher contains selector-drift detection before application apply.
- Selector migration deletes only incompatible Deployment controllers and uses
  foreground deletion with a bounded timeout.
- SPIRE token generation contains no incorrect `-spiffeID` override.
- All six workload entries use the resolved token-derived Agent ID as parent.

## Full local application integration test passed

A new process-level integration run was executed from the V7 source using six
generated CA-signed X.509 certificates containing the exact workload SPIFFE URI
SANs. The services communicated over TLS 1.3. The run verified:

1. Home, Architecture, every component page, and Control Panel returned HTTP 200.
2. The topology API returned six workloads plus OPA and SPIRE.
3. Every workload returned its expected SPIFFE ID and X.509 metadata.
4. Order Client sent an allowed `GET /api/orders` through the Gateway.
5. Authorized POST and PUT operations succeeded.
6. Repeated sensitive requests were denied and quarantined Report Client.
7. A normally authorized route was denied while quarantined.
8. Administrative release reset risk and restored normal traffic.
9. A continuous request job was cancelled successfully.
10. Direct Order Client access to Protected API was rejected at mTLS.

The final integration output was:

```text
READY
PAGES OK
IDENTITIES OK
ALLOWED OK
POST/PUT OK
QUARANTINE OK
RELEASE OK
CANCEL OK
DIRECT ACCESS BLOCKED
FULL END-TO-END INTEGRATION PASS
```

The local integration test used a policy-compatible OPA HTTP endpoint to
exercise the full Go request path. The Kubernetes deployment uses the packaged
OPA sidecar and Rego policy.

## Mandatory real-cluster verification

This Linux validation environment cannot execute the user's Windows Docker
Desktop and kind cluster. The launcher therefore performs the remaining proof
on the user's machine and will not print `ContainGo is ready` or open the
browser until the actual cluster passes:

- SPIRE Server and token-derived Agent verification;
- six registration entries and six issued workload SVIDs;
- successful rollout of all six compatible/recreated Deployments;
- authenticated GET/POST/PUT traffic;
- OPA allow/deny behavior;
- trace persistence;
- risk, quarantine, release, and recovered traffic; and
- continuous-job cancellation.

Any failure writes Kubernetes, pod, container, SPIRE and host-socket diagnostics
under `.containgo/logs/`.
