# ContainGo Architecture

## Runtime flow

```mermaid
flowchart LR
    OC[Order Client] -->|SPIFFE mTLS| GW[API Gateway]
    RC[Report Client] -->|SPIFFE mTLS| GW
    CP[Control Plane] -->|SPIFFE mTLS: quarantine data| GW
    GW --> OPA[OPA sidecar]
    GW -->|SPIFFE mTLS| PA[Protected API]
    GW -->|trusted decision event over SPIFFE mTLS| CP
    CP --> DB[(SQLite)]
    D[Dashboard] -->|SPIFFE mTLS| CP
    CLI[democtl] -->|SPIFFE mTLS| CP
    CLI -->|SPIFFE mTLS: mode control| RC
    SPIRE[SPIRE Workload API] -. rotating X.509-SVIDs .-> OC
    SPIRE -.-> RC
    SPIRE -.-> GW
    SPIRE -.-> PA
    SPIRE -.-> CP
    SPIRE -.-> D
    SPIRE -.-> CLI
```

## Request processing

1. A workload establishes mTLS with the API Gateway.
2. The Gateway extracts the authenticated SPIFFE ID from the verified X.509-SVID.
3. The Gateway sends the workload ID, HTTP method, path, and quarantine data to OPA.
4. OPA returns an allow or deny decision.
5. The Gateway emits a trusted security event to the Control Plane.
6. The Control Plane calculates server-owned contributions and persists the event.
7. When the score reaches 70, the Control Plane creates an incident and adds the workload to the Gateway's OPA quarantine data.
8. Future requests from that workload are denied while unrelated workloads continue.
9. Release closes the incident, resets risk, removes OPA quarantine data, and preserves audit history.

## Incident evidence

Risk contributions remain positive until release or explicit reset. At quarantine time, the Control Plane reads persisted events newest-first and reconstructs the newest complete contribution suffix whose points exactly equal the current score. The incident stores those contributions chronologically. This excludes older events belonging to a previous reset cycle while ensuring that new incident reason points match `score_at_quarantine`.

## Availability model

Kubernetes readiness uses local service health and does not create a circular dependency between the API Gateway and Control Plane. The deployment script restarts components in dependency order:

```text
Protected API → API Gateway → Control Plane → clients → Dashboard → democtl
```

SPIRE and Calico installers are safe to rerun against an already healthy local cluster.
