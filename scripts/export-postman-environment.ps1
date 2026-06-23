param(
    [string]$ClusterName = "containgo",
    [int]$LocalPort = 8060,
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$context = "kind-$ClusterName"

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $projectRoot "postman\ContainGo.local.generated.postman_environment.json"
}

$encoded = kubectl `
    --context $context `
    --namespace containgo `
    get secret containgo-demo-api `
    -o jsonpath='{.data.token}'

if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($encoded)) {
    throw "ContainGo demo API token secret is unavailable."
}

$token = [System.Text.Encoding]::UTF8.GetString(
    [System.Convert]::FromBase64String($encoded)
)

$environment = [ordered]@{
    id = [guid]::NewGuid().ToString()
    name = "ContainGo Local Demo"
    values = @(
        [ordered]@{
            key = "base_url"
            value = "http://127.0.0.1:$LocalPort"
            type = "default"
            enabled = $true
        },
        [ordered]@{
            key = "demo_token"
            value = $token
            type = "secret"
            enabled = $true
        }
    )
    _postman_variable_scope = "environment"
    _postman_exported_at = (Get-Date).ToUniversalTime().ToString("o")
    _postman_exported_using = "ContainGo export-postman-environment.ps1"
}

$directory = Split-Path -Parent $OutputPath
New-Item -ItemType Directory -Force $directory | Out-Null
$environment | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8

Write-Host "Postman environment written to: $OutputPath"
Write-Host "Import it together with postman\ContainGo.postman_collection.json"
