[CmdletBinding()]
param(
    [string]$ClusterName = 'containgo',
    [switch]$StopCluster,
    [switch]$DeleteCluster
)
try {
    & (Join-Path $PSScriptRoot 'containGo\scripts\stop-containgo.ps1') -ClusterName $ClusterName -StopCluster:$StopCluster -DeleteCluster:$DeleteCluster
    if (-not $?) { exit 1 }
} catch {
    Write-Error $_
    exit 1
}
