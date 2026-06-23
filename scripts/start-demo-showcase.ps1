param(
    [string]$ClusterName = "containgo",
    [int]$LocalPort = 8060,
    [switch]$OpenBrowser
)

$ErrorActionPreference = "Stop"

& (Join-Path $PSScriptRoot "export-postman-environment.ps1") `
    -ClusterName $ClusterName `
    -LocalPort $LocalPort

& (Join-Path $PSScriptRoot "show-demo-access.ps1") `
    -ClusterName $ClusterName `
    -LocalPort $LocalPort

if ($OpenBrowser) {
    Start-Process "http://127.0.0.1:$LocalPort/demo"
}

Write-Host ""
Write-Host "Starting Dashboard port-forward. Press Ctrl+C to stop."

& (Join-Path $PSScriptRoot "port-forward-dashboard.ps1") `
    -ClusterName $ClusterName `
    -LocalPort $LocalPort
