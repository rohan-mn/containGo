param(
    [string]$ClusterName = "containgo",
    [int]$TimeoutSeconds = 600
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$context = "kind-$ClusterName"
$manifestPath = Join-Path $projectRoot "deploy\kubernetes"

Write-Host "Installing SPIRE..."

& (Join-Path $PSScriptRoot "install-spire.ps1") `
    -KubeContext $context `
    -ChartVersion "0.29.0" `
    -CRDChartVersion "0.5.0" `
    -TimeoutSeconds $TimeoutSeconds

Write-Host ""
Write-Host "Preparing the local-only Dashboard demo API token..."

$existingSecret = kubectl `
    --context $context `
    --namespace containgo `
    get secret containgo-demo-api `
    --ignore-not-found `
    --output name `
    2>$null

if ($LASTEXITCODE -ne 0) {
    throw "Failed to check for the Dashboard demo API token."
}

$existingSecret = (
    $existingSecret |
        Out-String
).Trim()

if ([string]::IsNullOrWhiteSpace($existingSecret)) {
    $tokenBytes = New-Object byte[] 32
    $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()

    try {
        $random.GetBytes($tokenBytes)
    }
    finally {
        $random.Dispose()
    }

    $demoToken = [System.Convert]::ToBase64String(
        $tokenBytes
    )

    $demoToken = $demoToken.
        TrimEnd('=').
        Replace('+', '-').
        Replace('/', '_')

    kubectl `
        --context $context `
        --namespace containgo `
        create secret generic containgo-demo-api `
        --from-literal="token=$demoToken"

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create the Dashboard demo API token."
    }

    Write-Host "Created containgo-demo-api secret."
}
else {
    Write-Host "Reusing existing containgo-demo-api secret."
}

if ($LASTEXITCODE -ne 0) {
    $tokenBytes = New-Object byte[] 32
    $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $random.GetBytes($tokenBytes)
    }
    finally {
        $random.Dispose()
    }

    $demoToken = [System.Convert]::ToBase64String($tokenBytes)
    $demoToken = $demoToken.TrimEnd('=').Replace('+', '-').Replace('/', '_')

    kubectl `
        --context $context `
        --namespace containgo `
        create secret generic containgo-demo-api `
        --from-literal="token=$demoToken"

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create the Dashboard demo API token."
    }
}
else {
    Write-Host "Reusing existing containgo-demo-api secret."
}

Write-Host ""
Write-Host "Applying ContainGo Kubernetes resources..."

kubectl `
    --context $context `
    apply `
    --kustomize $manifestPath

if ($LASTEXITCODE -ne 0) {
    throw "ContainGo manifest application failed."
}

Write-Host ""
Write-Host "Waiting for the SQLite PVC..."

kubectl `
    --context $context `
    --namespace containgo `
    wait `
    --for=jsonpath='{.status.phase}'=Bound `
    pvc/containgo-sqlite `
    --timeout="${TimeoutSeconds}s"

if ($LASTEXITCODE -ne 0) {
    throw "SQLite PVC did not bind."
}

# Images use the local :dev tag. An ordered restart ensures newly loaded kind
# images and ConfigMap changes are picked up, while dependencies become ready
# before their callers restart.
$deploymentOrder = @(
    "protected-api",
    "api-gateway",
    "control-plane",
    "order-client",
    "report-client",
    "dashboard",
    "democtl"
)

Write-Host ""
Write-Host "Restarting ContainGo Deployments in dependency order..."

foreach ($deployment in $deploymentOrder) {
    kubectl `
        --context $context `
        --namespace containgo `
        rollout restart `
        "deployment/$deployment"

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to restart deployment '$deployment'."
    }

    kubectl `
        --context $context `
        --namespace containgo `
        rollout status `
        "deployment/$deployment" `
        --timeout="${TimeoutSeconds}s"

    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "Deployment '$deployment' did not become ready."
        kubectl `
            --context $context `
            --namespace containgo `
            get pods `
            -o wide
        throw "ContainGo deployment rollout failed."
    }
}

Write-Host ""
Write-Host "ContainGo is deployed."
kubectl --context $context --namespace containgo get pods -o wide
Write-Host ""
Write-Host "Run .\scripts\show-demo-access.ps1 to view UI and Postman access details."
