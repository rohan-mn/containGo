param(
    [string]$ClusterName = "containgo",
    [int]$LocalPort = 8060
)

$ErrorActionPreference = "Stop"
$context = "kind-$ClusterName"

Write-Host "Dashboard overview: http://127.0.0.1:$LocalPort"
Write-Host "Guided demo:       http://127.0.0.1:$LocalPort/demo"
Write-Host "Architecture:      http://127.0.0.1:$LocalPort/architecture"
Write-Host "Press Ctrl+C to stop port-forwarding."

kubectl `
    --context $context `
    --namespace containgo `
    port-forward `
    service/dashboard `
    "${LocalPort}:8060"
