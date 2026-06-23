param(
    [string]$ClusterName = "containgo",
    [switch]$Recreate
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$configPath = Join-Path $projectRoot "deploy\kind\cluster.yaml"

if (-not (Test-Path $configPath)) {
    throw "kind configuration not found: $configPath"
}

$existing = kind get clusters

if ($existing -contains $ClusterName) {
    if (-not $Recreate) {
        Write-Host "kind cluster '$ClusterName' already exists."
        exit 0
    }

    Write-Host "Deleting existing kind cluster '$ClusterName'..."
    kind delete cluster --name $ClusterName
}

Write-Host "Creating kind cluster '$ClusterName' without the default CNI..."

kind create cluster `
    --name $ClusterName `
    --config $configPath

if ($LASTEXITCODE -ne 0) {
    throw "kind cluster creation failed."
}

$nodeContainer = "${ClusterName}-control-plane"

Write-Host "Preparing SQLite hostPath inside $nodeContainer..."

docker exec $nodeContainer `
    sh -c "mkdir -p /var/lib/containgo && chown -R 65532:65532 /var/lib/containgo && chmod 0770 /var/lib/containgo"

if ($LASTEXITCODE -ne 0) {
    throw "Could not prepare the SQLite directory inside the kind node."
}

Write-Host ""
Write-Host "kind cluster created. Nodes remain NotReady until Calico is installed."
Write-Host "Kubernetes context: kind-$ClusterName"
