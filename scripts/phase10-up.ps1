param(
    [string]$ClusterName = "containgo",
    [switch]$RecreateCluster,
    [switch]$NoCache,
    [int]$TimeoutSeconds = 600
)

$ErrorActionPreference = "Stop"

& (Join-Path $PSScriptRoot "phase10-prereqs.ps1")

& (Join-Path $PSScriptRoot "create-kind-cluster.ps1") `
    -ClusterName $ClusterName `
    -Recreate:$RecreateCluster

& (Join-Path $PSScriptRoot "install-calico.ps1") `
    -ClusterName $ClusterName `
    -Version "v3.32.0" `
    -TimeoutSeconds $TimeoutSeconds

& (Join-Path $PSScriptRoot "build-kind-images.ps1") `
    -ClusterName $ClusterName `
    -NoCache:$NoCache

& (Join-Path $PSScriptRoot "deploy-containgo.ps1") `
    -ClusterName $ClusterName `
    -TimeoutSeconds $TimeoutSeconds

Write-Host ""
Write-Host "Phase 10 stack is ready."
Write-Host "Dashboard:"
Write-Host "  .\scripts\port-forward-dashboard.ps1 -ClusterName $ClusterName"
Write-Host ""
Write-Host "Demo:"
Write-Host "  .\scripts\democtl-k8s.ps1 status -ClusterName $ClusterName"
