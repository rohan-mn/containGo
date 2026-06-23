param(
    [string]$ClusterName = "containgo",
    [int]$LocalPort = 8060
)

$ErrorActionPreference = "Stop"
$context = "kind-$ClusterName"

$encoded = kubectl `
    --context $context `
    --namespace containgo `
    get secret containgo-demo-api `
    -o jsonpath='{.data.token}'

if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($encoded)) {
    throw "ContainGo demo API token secret is unavailable. Run deploy-containgo.ps1 first."
}

$token = [System.Text.Encoding]::UTF8.GetString(
    [System.Convert]::FromBase64String($encoded)
)

Write-Host ""
Write-Host "ContainGo guided demo"
Write-Host "  UI:        http://127.0.0.1:$LocalPort/demo"
Write-Host "  Overview:  http://127.0.0.1:$LocalPort/"
Write-Host "  Postman:   http://127.0.0.1:$LocalPort/demo-api/v1"
Write-Host "  Header:    X-ContainGo-Demo-Token"
Write-Host "  Token:     $token"
Write-Host ""
Write-Host "Start the port-forward in a separate terminal:"
Write-Host ".\scripts\port-forward-dashboard.ps1 -ClusterName $ClusterName -LocalPort $LocalPort"
