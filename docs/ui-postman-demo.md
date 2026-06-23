# ContainGo UI and Postman Demonstration

This demonstration shows the complete ContainGo security lifecycle without
requiring the audience to follow terminal logs.

## Prepare the updated deployment

```powershell
Set-Location C:\Projects\containGo

gofmt -w .
go test ./...
go vet ./...

.\scripts\build-kind-images.ps1 -ClusterName containgo
.\scripts\deploy-containgo.ps1 -ClusterName containgo -TimeoutSeconds 900
```

The deployment creates a random local-only Dashboard demo API token and stores
it in the `containgo-demo-api` Kubernetes Secret.

## Start the browser UI

In terminal 1:

```powershell
.\scripts\port-forward-dashboard.ps1 -ClusterName containgo
```

Open:

```text
http://127.0.0.1:8060/demo
```

The Demo Console refreshes every five seconds and provides four workload modes,
a reset action, an automatic safe release action, live counters, OPA policy
matrix, request events, complete incident evidence and audit history.

## Recommended presenter script

### 1. Explain the architecture

Open the **Architecture** page and show:

- seven SPIFFE workload identities;
- SPIRE X.509-SVID issuance and rotation;
- mTLS between internal components;
- API Gateway identity extraction;
- OPA identity-and-route authorization;
- Control Plane risk scoring and quarantine;
- SQLite incident and audit persistence;
- default-deny NetworkPolicies.

### 2. Reset the demonstration

Open **Demo Console** and select **Reset demo**. Confirm:

- Report Client mode is `normal`;
- Report Client is `active`;
- current risk is `0`;
- request counters start clean;
- normal `/api/reports` calls return `200`.

### 3. Demonstrate a rate anomaly

Select **Rapid burst**. Explain that the requests are policy-allowed, but the
volume is anomalous. The Control Plane adds the request-rate contribution.
Return to **Normal** after the score appears.

### 4. Demonstrate attack and quarantine

Select **Attack**. The Report Client attempts:

```text
GET /api/payment-details
GET /api/admin/config
```

Within a few seconds the UI shows:

- OPA denials with HTTP `403`;
- risk contributions `25 + 40 + 25 + 35 = 125`;
- Report Client status `quarantined`;
- Order Client status still `active`;
- incident evidence total equal to quarantine score.

After quarantine, even the normally allowed report endpoint is denied because
quarantine overrides the normal route policy.

### 5. Release and recover

Select **Release quarantined workload**. The UI first changes the workload back
to normal behavior, then releases it. Show:

- workload returns to `active`;
- risk and denied counters return to `0`;
- `/api/reports` returns `200` again;
- the incident remains stored as `released`;
- audit records show `incident_released`, `workload_released` and
  `opa_quarantine_removed` with the Dashboard SPIFFE identity as actor.

## Configure Postman

Keep the Dashboard port-forward running.

Generate a Postman environment containing the actual random token:

```powershell
.\scripts\export-postman-environment.ps1 -ClusterName containgo
```

Import these files into Postman:

```text
postman/ContainGo.postman_collection.json
postman/ContainGo.local.generated.postman_environment.json
```

Select **ContainGo Local Demo** as the active environment and run the collection
in numeric order.

Postman talks only to the localhost Dashboard facade. The Dashboard then calls
the Control Plane and Report Client over SPIFFE mTLS. This preserves the
credentialless workload-identity design; Postman is not given a static SPIFFE
private key.

## Postman endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/demo-api/v1/state` | Complete live demo state |
| `POST` | `/demo-api/v1/mode` | Set normal, rapid, attack or paused mode |
| `POST` | `/demo-api/v1/release` | Safe normal-mode release |
| `POST` | `/demo-api/v1/reset` | Clean demo state and counters |
| `GET` | `/demo-api/v1/workloads` | Seven registered workloads |
| `GET` | `/demo-api/v1/report-client/evidence` | Events, incidents and audit evidence |

Every Postman request must include:

```text
X-ContainGo-Demo-Token: {{demo_token}}
```

## Important security explanation

The Postman facade is intended only for the local demonstration environment:

- Dashboard remains a Kubernetes `ClusterIP` Service;
- access is through `kubectl port-forward` to localhost;
- a random token protects the facade;
- backend communication remains SPIFFE mTLS;
- no static SPIFFE private key is exported to Postman;
- NetworkPolicies permit Dashboard access only to Control Plane and Report Client.

## One-command presenter setup

The following command exports the Postman environment, prints the local token,
opens the guided UI and starts the blocking port-forward:

```powershell
.\scripts\start-demo-showcase.ps1 `
    -ClusterName containgo `
    -OpenBrowser
```
