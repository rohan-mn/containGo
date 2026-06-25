# ContainGo : An Interactive SPIFFE Workload Management Lab

ContainGo is a local, end-to-end zero-trust demonstration platform built with Go, Docker, kind Kubernetes, Calico, SPIFFE/SPIRE, mutual TLS, Open Policy Agent, a persistent risk engine, and an interactive browser console.

The project is intentionally designed so that the UI does **not** impersonate workloads. When an operator selects `order-client` or `report-client`, the Dashboard sends an authenticated control command to that workload. The selected workload then originates the real business request with its own short-lived X.509-SVID.

## One-command start

### Prerequisites

- Windows 10 or Windows 11.
- Docker Desktop configured for **Linux containers**.
- Internet access on the first run so Docker images, kind, kubectl, Calico, SPIRE, and OPA can be downloaded.
- PowerShell 5.1 or newer.

Go, kind, and kubectl do not need to be installed globally. The launcher downloads pinned local copies of kind and kubectl when they are missing.

From the extracted package root, run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\RUN-CONTAINGO.ps1
```

The script:

1. Starts Docker Desktop when it is installed but stopped.
2. Explains Docker/WSL/Linux-container failures when Docker cannot start.
3. Downloads pinned `kind` and `kubectl` binaries locally when needed.
4. Creates, recovers, or repairs the `containgo` kind cluster.
5. Installs Calico and waits for cluster networking and DNS.
6. Builds the Go application and SPIFFE Helper images.
7. Starts SPIRE Server and SPIRE Agent.
8. Registers each workload identity and provisions rotating X.509-SVIDs.
9. Deploys all application workloads and OPA.
10. Applies default-deny NetworkPolicies.
11. Waits for every rollout and readiness probe.
12. Starts a Dashboard port-forward.
13. Runs a full end-to-end verification of all six SVIDs, authenticated request paths, OPA decisions, traces, risk, quarantine, release, recovery, and job cancellation.
14. Opens the browser only after verification passes.

The default URL is:

```text
http://127.0.0.1:8060
```

### Useful start options

```powershell
# Recreate an inconsistent cluster if normal recovery fails
.\RUN-CONTAINGO.ps1 -Repair

# Force the local images to rebuild
.\RUN-CONTAINGO.ps1 -RebuildImages

# Use another host port
.\RUN-CONTAINGO.ps1 -DashboardPort 9060

# Start without opening a browser
.\RUN-CONTAINGO.ps1 -NoBrowser

# Diagnostic escape hatch only: skip the final application smoke test
.\RUN-CONTAINGO.ps1 -SkipSmokeTest
```

### Stop or remove the environment

```powershell
# Stop only the Dashboard port-forward
.\STOP-CONTAINGO.ps1

# Stop the kind node container; RUN-CONTAINGO.ps1 will recover it later
.\STOP-CONTAINGO.ps1 -StopCluster

# Permanently delete the local kind cluster
.\STOP-CONTAINGO.ps1 -DeleteCluster
```


## Built-in release verification

By default, startup does not stop at Kubernetes rollout success. After the Dashboard port-forward becomes ready, the launcher automatically verifies:

- all six workload X.509-SVIDs and expected SPIFFE IDs;
- `GET /api/orders`, `POST /api/orders`, `PUT /api/orders/ORD-1001`, and `POST /api/reports/generate`;
- OPA allow and deny decisions;
- persisted correlated trace evidence across the client, Gateway, OPA, Protected API, and Control Plane;
- risk accumulation and automatic quarantine;
- denial of normally authorized traffic while quarantined;
- administrative release and restored normal traffic;
- resolved incident state; and
- cancellation of a continuous request job.

A failed verification is treated as startup failure and produces diagnostics under `containGo/.containgo/logs/`. `-SkipSmokeTest` exists only as a troubleshooting escape hatch.

## User interface

### Home — `/`

Shows platform status, workload inventory, quarantine count, risk totals, and recent evidence.

### Interactive architecture — `/architecture`

Shows the real runtime topology:

```text
Browser
  │
  ▼
Dashboard
  ├── SPIFFE mTLS control ──> Order Client
  └── SPIFFE mTLS control ──> Report Client
                                  │
Order Client / Report Client ─────┘
               │ their own X.509-SVID
               ▼
          API Gateway ──localhost──> OPA sidecar
               │
               ├── Gateway X.509-SVID ──> Protected API
               └── Gateway X.509-SVID ──> Control Plane
                                             │
                                             ├── risk scoring
                                             ├── incident creation
                                             └── quarantine state
```

Clicking a node opens `/dashboard/<component>` in a new browser tab. Live Server-Sent Events animate the actual edges traversed by a request and show TLS version, cipher suite, source and peer SPIFFE IDs, SVID serial information, policy decision, risk delta, and quarantine result.

### Component inspectors — `/dashboard/<component>`

Available inspectors include:

- `/dashboard/order-client`
- `/dashboard/report-client`
- `/dashboard/api-gateway`
- `/dashboard/protected-api`
- `/dashboard/control-plane`
- `/dashboard/dashboard`
- `/dashboard/opa`
- `/dashboard/spire`

The client inspectors include a real request executor with:

- GET, POST, PUT, and DELETE.
- Registered endpoint selection.
- JSON request bodies.
- Up to 1,000 requests per finite job.
- Up to 50 concurrent workers.
- Configurable intervals.
- Continuous traffic until cancelled, with a ten-minute safety cap.
- A one-click quarantine sequence.
- A rate-anomaly burst preset.

### Control Panel — `/control-panel`

Shows:

- All six application workloads.
- Current risk scores.
- Allowed and denied request totals.
- Quarantined workloads.
- Open and resolved incidents.
- Evidence timelines.
- Release and risk-reset actions.

## Real API routes

### Order Client normally allowed

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/orders` | List orders |
| POST | `/api/orders` | Create an order |
| PUT | `/api/orders/ORD-1001` | Update an order |
| DELETE | `/api/orders/ORD-1001` | Delete an order |

### Report Client normally allowed

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/reports` | List reports |
| POST | `/api/reports/generate` | Generate a report |
| GET | `/api/customers` | List customer summaries |

### Intentionally protected routes

| Method | Endpoint | Risk effect after denial |
|---|---|---|
| GET | `/api/payment-details` | `25 unauthorized + 40 sensitive = 65` |
| PUT/POST | `/api/admin/config` | `25 unauthorized + 35 administrative = 60` |

The default quarantine threshold is 100. A payment-details attempt followed by an administrative configuration attempt produces 125 points and quarantines the caller.

## Workload identities

| Workload | SPIFFE ID | Local UID selector |
|---|---|---:|
| API Gateway | `spiffe://containgo.local/ns/containgo/sa/api-gateway` | 10001 |
| Control Plane | `spiffe://containgo.local/ns/containgo/sa/control-plane` | 10002 |
| Dashboard | `spiffe://containgo.local/ns/containgo/sa/dashboard` | 10003 |
| Order Client | `spiffe://containgo.local/ns/containgo/sa/order-client` | 10004 |
| Report Client | `spiffe://containgo.local/ns/containgo/sa/report-client` | 10005 |
| Protected API | `spiffe://containgo.local/ns/containgo/sa/protected-api` | 10006 |

This local learning environment uses a join token for SPIRE Agent node attestation and the Unix process UID workload attestor. Kubernetes ServiceAccounts and pod labels still make each workload visible as a distinct Kubernetes identity boundary. For production, replace this convenient local setup with a Kubernetes-native node attestor such as `k8s_psat`, Kubernetes workload selectors, an external CA, and a hardened SPIRE deployment.

## Risk rules

| Rule | Points |
|---|---:|
| Any denied or failed authorization | 25 |
| Attempt to access `/api/payment-details` | +40 |
| Attempt to modify `/api/admin/config` | +35 |
| More than 20 requests in five seconds | +50, once per 30-second penalty window |

The Control Plane persists state to the `control-plane-data` PersistentVolumeClaim. Stopping and restarting the cluster preserves risk, events, and incidents. Deleting the cluster removes that local data.

## PowerShell diagnostics

Logs are written under:

```text
containGo/.containgo/logs/
```

If startup fails, the launcher captures:

- `docker info` and container state.
- Kubernetes pods across all namespaces.
- Kubernetes events ordered by time.
- Descriptions of unhealthy pods.
- Current and previous logs for every container in unhealthy pods.

Typical failures are reported with a specific explanation, including:

- Docker Desktop not running.
- Docker Engine unreachable.
- Windows-container mode enabled.
- WSL-related Docker failures.
- Missing or stale kind node containers.
- Kubernetes API failure.
- Calico or CoreDNS rollout failure.
- SPIRE Server or Agent failure.
- Missing SVIDs.
- OPA readiness failure.
- PVC or mount errors.
- CrashLoopBackOff or ImagePullBackOff.
- Dashboard host-port conflicts.

## Postman

Import:

```text
postman/ContainGo.postman_collection.json
postman/ContainGo.local.postman_environment.json
```

Postman calls the Dashboard's authenticated workload-control façade. The Dashboard then commands the selected client, and the selected client originates the request with its own SPIFFE identity. Postman never supplies or impersonates a SPIFFE ID.

## Repository layout

```text
cmd/                         Go service entry points
internal/platform/           TLS, SVID, HTTP, trace and endpoint primitives
internal/clientservice/      Request-job executor used by both clients
internal/controlservice/     Persistent risk, incident and quarantine engine
internal/uiconsole/          Dashboard backend and embedded browser UI
policies/                    OPA authorization policy and tests
build/docker/                Application and SPIFFE Helper images
deploy/kind/                 kind cluster configuration
deploy/spire/                SPIRE Server, Agent, helper and local demo CA
deploy/kubernetes/           Application Deployments, Services and NetworkPolicies
scripts/                     One-click startup, recovery, cleanup and shutdown
postman/                     Collection and local environment
docs/                        Architecture, demo, and troubleshooting guides
```

## Security notes

- The browser cannot choose a SPIFFE ID.
- Only the Dashboard identity can invoke a client control API.
- Only business client identities can call Gateway business routes.
- Only the Gateway identity can call Protected API business routes.
- Only the Gateway identity can publish trusted security evidence.
- Only the Dashboard identity can release quarantined workloads.
- Request destinations are selected from a fixed endpoint catalogue, preventing the executor from becoming an arbitrary SSRF client.
- Request bodies are limited to 64 KiB.
- Private keys and raw Kubernetes secrets are never exposed in the UI.
- `deploy/spire/root-ca.key` is intentionally included only to make this local lab self-contained. Never reuse it outside this demonstration.
