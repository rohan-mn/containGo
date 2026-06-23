param(
    [string]$ClusterName = "containgo",
    [int]$DeployTimeoutSeconds = 900,
    [int]$VerifyTimeoutSeconds = 300,
    [switch]$SkipStaticChecks,
    [switch]$SkipImageBuild,
    [switch]$ExerciseRecovery,
    [switch]$SkipNetworkIsolation
)

$ErrorActionPreference = "Stop"

function Invoke-PhaseScript {
    param(
        [string]$Path,
        [hashtable]$Parameters = @{}
    )

    Write-Host ""
    Write-Host "============================================================"
    Write-Host "Running $([System.IO.Path]::GetFileName($Path))"
    Write-Host "============================================================"

    & $Path @Parameters

    if ($LASTEXITCODE -ne 0) {
        throw "$Path exited with code $LASTEXITCODE."
    }
}

if (-not $SkipStaticChecks) {
    Invoke-PhaseScript `
        -Path (Join-Path $PSScriptRoot "phase11-static-checks.ps1")

    Invoke-PhaseScript `
        -Path (Join-Path $PSScriptRoot "test-opa-policy.ps1")
}

if (-not $SkipImageBuild) {
    Invoke-PhaseScript `
        -Path (Join-Path $PSScriptRoot "build-kind-images.ps1") `
        -Parameters @{
            ClusterName = $ClusterName
        }
}

Invoke-PhaseScript `
    -Path (Join-Path $PSScriptRoot "deploy-containgo.ps1") `
    -Parameters @{
        ClusterName    = $ClusterName
        TimeoutSeconds = $DeployTimeoutSeconds
    }

$verificationParameters = @{
    ClusterName    = $ClusterName
    TimeoutSeconds = $VerifyTimeoutSeconds
}

if ($ExerciseRecovery) {
    $verificationParameters.ExerciseRecovery = $true
}

if ($SkipNetworkIsolation) {
    $verificationParameters.SkipNetworkIsolation = $true
}

Invoke-PhaseScript `
    -Path (Join-Path $PSScriptRoot "phase11-verify.ps1") `
    -Parameters $verificationParameters

Write-Host ""
Write-Host "ContainGo Phase 11 completed successfully."
