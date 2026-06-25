[CmdletBinding()]
param(
    [string]$ClusterName = 'containgo',
    [switch]$StopCluster,
    [switch]$DeleteCluster
)
$RepositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'lib\Common.ps1')
Require-Windows
$toolDirectory = Join-Path $RepositoryRoot '.containgo\tools'
Add-ToolPath $toolDirectory
$pidFile = Join-Path $RepositoryRoot '.containgo\dashboard-port-forward.pid'
Stop-SavedProcess $pidFile
Write-Ok 'Dashboard port-forward stopped.'
if ($DeleteCluster) {
    if (-not (Get-Command kind -ErrorAction SilentlyContinue)) { throw 'kind was not found. Run RUN-CONTAINGO.ps1 once, or install kind.' }
    Invoke-Native -File 'kind' -Arguments @('delete','cluster','--name',$ClusterName)
    Write-Ok "Cluster '$ClusterName' deleted."
} elseif ($StopCluster) {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Docker CLI was not found.' }
    Invoke-Native -File 'docker' -Arguments @('stop',"$ClusterName-control-plane")
    Write-Ok "Cluster '$ClusterName' stopped. The start script will recover it later."
}
