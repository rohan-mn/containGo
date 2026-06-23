param(
    [string]$OPACommand = "opa",
    [string]$Address = "127.0.0.1:8181"
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$policyPath = Join-Path `
    $projectRoot `
    "policies\containgo.rego"

if (-not (Test-Path $policyPath)) {
    throw "OPA policy not found: $policyPath"
}

Write-Host "Checking OPA policy..."

& $OPACommand check $policyPath

if ($LASTEXITCODE -ne 0) {
    throw "OPA policy validation failed."
}

Write-Host "Starting OPA on $Address..."
Write-Host "Policy: $policyPath"

& $OPACommand run `
    --server `
    --addr $Address `
    $policyPath

exit $LASTEXITCODE