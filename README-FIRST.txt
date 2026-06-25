CONTAINGO INTERACTIVE WORKLOAD QUARANTINE LAB - V7

1. Keep Docker Desktop running in Linux-container mode.
2. Extract this package over the previous ContainGo-Interactive folder and allow
   Windows to replace the existing files.
3. Open PowerShell in the extracted folder.
4. Run:

   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\RUN-CONTAINGO.ps1

5. The launcher opens http://127.0.0.1:8060 only after the real Kubernetes
   deployment passes the built-in end-to-end verification.

V7 preserves the working SPIRE join-token Agent logic from V5 and adds a safe
migration for Kubernetes Deployment selector changes. Existing incompatible
Deployments are recreated while Services, SPIRE state and persistent Control
Plane storage remain in place. V7 also fixes the Dashboard readiness/liveness
probe port to match the Dashboard's actual HTTP listener on 8060.

Detailed documentation is in containGo\README.md.
Validation details are in containGo\VALIDATION.md.
Field-fix details are in PATCH-NOTES.txt.
