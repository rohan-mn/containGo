[CmdletBinding()]
param(
    [string]$ClusterName = 'containgo',
    [int]$DashboardPort = 8060,
    [switch]$Repair,
    [switch]$RebuildImages,
    [switch]$NoBrowser,
    [switch]$SkipSmokeTest
)
$script = Join-Path $PSScriptRoot 'containGo\scripts\start-containgo.ps1'

# Parse every launcher script with the PowerShell parser available on the user's
# machine before executing any Docker or Kubernetes mutation. This catches archive
# corruption and runtime-specific syntax problems with a clear message.
$scriptFiles = @(
    $PSCommandPath,
    (Join-Path $PSScriptRoot 'STOP-CONTAINGO.ps1'),
    (Join-Path $PSScriptRoot 'containGo\scripts\start-containgo.ps1'),
    (Join-Path $PSScriptRoot 'containGo\scripts\stop-containgo.ps1'),
    (Join-Path $PSScriptRoot 'containGo\scripts\remove-obsolete.ps1'),
    (Join-Path $PSScriptRoot 'containGo\scripts\lib\Common.ps1')
)
foreach ($file in $scriptFiles) {
    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) {
        $details = ($parseErrors | ForEach-Object { "$($_.Extent.File):$($_.Extent.StartLineNumber): $($_.Message)" }) -join "`n"
        throw "PowerShell syntax validation failed before startup:`n$details"
    }
}
try {
    & $script -ClusterName $ClusterName -DashboardPort $DashboardPort -Repair:$Repair -RebuildImages:$RebuildImages -NoBrowser:$NoBrowser -SkipSmokeTest:$SkipSmokeTest
    if (-not $?) { exit 1 }
} catch {
    Write-Error $_
    exit 1
}
