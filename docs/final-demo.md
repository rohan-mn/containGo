# Final Demonstration Runbook

## One-command completion

```powershell
.\scripts\phase11-complete.ps1 -ClusterName containgo
```

Use the steps below when presenting or troubleshooting each stage separately.

## 1. Verify source

```powershell
.\scripts\phase11-static-checks.ps1
```

## 2. Build and deploy

```powershell
.\scripts\build-kind-images.ps1 -ClusterName containgo

.\scripts\deploy-containgo.ps1 `
    -ClusterName containgo `
    -TimeoutSeconds 900
```

## 3. Run the automated acceptance test

```powershell
.\scripts\phase11-verify.ps1 `
    -ClusterName containgo `
    -TimeoutSeconds 300
```

A successful run ends with:

```text
ContainGo Phase 11 verification PASSED
```

## 4. Presenter-led flow

Start with normal status:

```powershell
.\scripts\democtl-k8s.ps1 status
```

Explain that both clients are active and normal requests return 200.

Trigger attack mode:

```powershell
.\scripts\democtl-k8s.ps1 attack
Start-Sleep -Seconds 10
.\scripts\democtl-k8s.ps1 status
```

Point out:

- restricted requests return 403;
- Report Client risk exceeds 70;
- Report Client becomes quarantined;
- Order Client remains active.

Show complete evidence:

```powershell
.\scripts\democtl-k8s.ps1 inspect-json report-client
```

The newest open incident's reason points should equal its quarantine score.

Release safely:

```powershell
.\scripts\democtl-k8s.ps1 normal
.\scripts\democtl-k8s.ps1 release report-client
Start-Sleep -Seconds 5
.\scripts\democtl-k8s.ps1 status
```

Point out that the workload is active with zero authoritative risk while the released incident and audit records remain stored.

## 5. Dashboard

```powershell
.\scripts\port-forward-dashboard.ps1 -ClusterName containgo
```

Open `http://127.0.0.1:8060` and show workload status, evidence, incidents, and audit history.

## 6. Optional resilience proof

```powershell
.\scripts\phase11-verify.ps1 -ExerciseRecovery
```

## 7. Optional credential rotation proof

```powershell
.\scripts\watch-svid-rotation.ps1 -Component api-gateway
```
