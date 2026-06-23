param(
    [switch]$Race
)

$ErrorActionPreference = "Stop"

function Require-Command {
    param([string]$Name)

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' was not found on PATH."
    }
}

function Invoke-Checked {
    param(
        [string]$Command,
        [string[]]$Arguments
    )

    Write-Host "> $Command $($Arguments -join ' ')"
    & $Command @Arguments

    if ($LASTEXITCODE -ne 0) {
        throw "$Command exited with code $LASTEXITCODE."
    }
}

Require-Command "go"
Require-Command "gofmt"

Set-Location (Split-Path -Parent $PSScriptRoot)

Write-Host "Checking Go formatting..."
$unformatted = @(gofmt -l .)
if ($unformatted.Count -gt 0) {
    Write-Host "The following files are not formatted:"
    $unformatted | ForEach-Object { Write-Host "  $_" }
    throw "Run 'gofmt -w .' before continuing."
}

$testArguments = @("test", "-count=1")
if ($Race) {
    $testArguments += "-race"
}
$testArguments += "./..."

Invoke-Checked "go" $testArguments
Invoke-Checked "go" @("vet", "./...")
Invoke-Checked "go" @(
    "build",
    "./cmd/protected-api",
    "./cmd/api-gateway",
    "./cmd/control-plane",
    "./cmd/order-client",
    "./cmd/report-client",
    "./cmd/dashboard",
    "./cmd/democtl"
)

Write-Host ""
Write-Host "Phase 11 static verification passed."
