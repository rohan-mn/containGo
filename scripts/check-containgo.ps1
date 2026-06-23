param(
    [string]$ClusterName = "containgo"
)

$ErrorActionPreference = "Stop"
$context = "kind-$ClusterName"

Write-Host "ContainGo pods:"
kubectl --context $context --namespace containgo get pods -o wide

Write-Host ""
Write-Host "ContainGo services:"
kubectl --context $context --namespace containgo get services

Write-Host ""
Write-Host "SQLite storage:"
kubectl --context $context get pv containgo-sqlite
kubectl --context $context --namespace containgo get pvc containgo-sqlite

Write-Host ""
Write-Host "SPIFFE identity registration:"
kubectl --context $context get clusterspiffeid containgo-workloads -o yaml

Write-Host ""
Write-Host "Recent application events:"
kubectl --context $context --namespace containgo get events --sort-by=.lastTimestamp |
    Select-Object -Last 25
