# Troubleshooting

## Docker CLI is not installed

Install Docker Desktop for Windows. The launcher can download kind and kubectl, but Docker Desktop is the required container engine.

## Docker Desktop does not start

Open Docker Desktop and inspect its diagnostics. Also run:

```powershell
wsl --status
docker info
```

The launcher distinguishes a stopped Desktop process, an unreachable engine, WSL-related errors, permissions errors, and Windows-container mode.

## Existing cluster cannot recover

```powershell
.\RUN-CONTAINGO.ps1 -Repair
```

This allows the launcher to delete inconsistent kind metadata and recreate the cluster.

## Port 8060 is occupied

```powershell
.\RUN-CONTAINGO.ps1 -DashboardPort 9060
```

## Force a clean image rebuild

```powershell
.\RUN-CONTAINGO.ps1 -RebuildImages
```

## Inspect cluster state manually

```powershell
kubectl --context kind-containgo get pods -A -o wide
kubectl --context kind-containgo get events -A --sort-by=.lastTimestamp
kubectl --context kind-containgo logs -n containgo deployment/api-gateway --all-containers
kubectl --context kind-containgo logs -n spire deployment/spire-server
kubectl --context kind-containgo logs -n spire daemonset/spire-agent
```

## Reset the entire lab

```powershell
.\STOP-CONTAINGO.ps1 -DeleteCluster
.\RUN-CONTAINGO.ps1
```
