param(
    [string]$ClusterName = "containgo",
    [string]$Version = "v3.32.0",
    [int]$TimeoutSeconds = 600
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$context = "kind-$ClusterName"
$resourcesPath = Join-Path $projectRoot "deploy\calico\custom-resources.yaml"

if (-not (Test-Path $resourcesPath)) {
    throw "Calico custom resources not found: $resourcesPath"
}

Write-Host "Checking whether Calico is already healthy..."

$statusNames = @(
    kubectl `
        --context $context `
        get tigerastatus.operator.tigera.io `
        -o name `
        2>$null
)

$statusesExist = (
    $LASTEXITCODE -eq 0 -and
    $statusNames.Count -gt 0
)

if ($statusesExist) {
    kubectl `
        --context $context `
        wait `
        --for=condition=Available `
        tigerastatus.operator.tigera.io `
        --all `
        --timeout="15s" `
        *> $null

    $statusesReady = $LASTEXITCODE -eq 0

    kubectl `
        --context $context `
        wait `
        --for=condition=Ready `
        nodes `
        --all `
        --timeout="15s" `
        *> $null

    $nodesReady = $LASTEXITCODE -eq 0

    if ($statusesReady -and $nodesReady) {
        Write-Host (
            "Calico is already installed and healthy; " +
            "skipping Helm installation."
        )
        return
    }
}

Write-Host "Adding the Calico Helm repository..."
helm repo add projectcalico https://docs.tigera.io/calico/charts --force-update
helm repo update projectcalico

Write-Host "Installing Calico CRDs..."
helm upgrade `
    --install `
    calico-crds `
    projectcalico/crd.projectcalico.org.v1 `
    --version $Version `
    --namespace tigera-operator `
    --create-namespace `
    --kube-context $context `
    --wait `
    --timeout "${TimeoutSeconds}s"

if ($LASTEXITCODE -ne 0) {
    throw "Calico CRD installation failed."
}

Write-Host "Installing the Tigera Operator..."
helm upgrade `
    --install `
    calico `
    projectcalico/tigera-operator `
    --version $Version `
    --namespace tigera-operator `
    --kube-context $context `
    --wait `
    --timeout "${TimeoutSeconds}s"

if ($LASTEXITCODE -ne 0) {
    throw "Tigera Operator installation failed."
}

Write-Host "Applying Calico installation resources..."
kubectl `
    --context $context `
    apply `
    --filename $resourcesPath

if ($LASTEXITCODE -ne 0) {
    throw "Calico custom-resource application failed."
}

Write-Host "Waiting for the Tigera Operator deployment..."
kubectl `
    --context $context `
    --namespace tigera-operator `
    rollout status `
    deployment/tigera-operator `
    --timeout="${TimeoutSeconds}s"

if ($LASTEXITCODE -ne 0) {
    kubectl `
        --context $context `
        --namespace tigera-operator `
        get pods `
        -o wide
    throw "Tigera Operator did not become ready."
}

Write-Host "Waiting for TigeraStatus resources to be created..."

$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$statusNames = @()

do {
    $statusNames = @(
        kubectl `
            --context $context `
            get tigerastatus.operator.tigera.io `
            -o name `
            2>$null
    )

    if ($LASTEXITCODE -eq 0 -and $statusNames.Count -gt 0) {
        break
    }

    Write-Host (
        "TigeraStatus resources are not available yet; " +
        "checking again in 5 seconds..."
    )
    Start-Sleep -Seconds 5
}
while ((Get-Date) -lt $deadline)

if ($statusNames.Count -eq 0) {
    Write-Host ""
    Write-Host "Tigera Operator pods:"
    kubectl `
        --context $context `
        --namespace tigera-operator `
        get pods `
        -o wide

    Write-Host ""
    Write-Host "Tigera Operator logs:"
    kubectl `
        --context $context `
        --namespace tigera-operator `
        logs `
        deployment/tigera-operator `
        --tail=200

    throw "The Tigera Operator did not create TigeraStatus resources."
}

Write-Host "Waiting for Calico components to become Available..."
kubectl `
    --context $context `
    wait `
    --for=condition=Available `
    tigerastatus.operator.tigera.io `
    --all `
    --timeout="${TimeoutSeconds}s"

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "Current Calico status:"
    kubectl `
        --context $context `
        get tigerastatus.operator.tigera.io `
        -o wide

    Write-Host ""
    Write-Host "Calico system pods:"
    kubectl `
        --context $context `
        --namespace calico-system `
        get pods `
        -o wide

    throw "Calico did not become Available."
}

Write-Host "Waiting for Kubernetes nodes..."
kubectl `
    --context $context `
    wait `
    --for=condition=Ready `
    nodes `
    --all `
    --timeout="${TimeoutSeconds}s"

if ($LASTEXITCODE -ne 0) {
    kubectl --context $context get nodes -o wide
    throw "Kubernetes nodes did not become Ready."
}

Write-Host ""
Write-Host "Calico networking and NetworkPolicy enforcement are ready."
