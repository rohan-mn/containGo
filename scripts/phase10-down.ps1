param(
    [string]$ClusterName = "containgo"
)

$ErrorActionPreference = "Stop"

kind delete cluster --name $ClusterName

if ($LASTEXITCODE -ne 0) {
    throw "Could not delete kind cluster '$ClusterName'."
}

Write-Host "kind cluster '$ClusterName' deleted."
