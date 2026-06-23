param(
    [string]$KubeContext = "",
    [string]$Namespace = "spire",
    [string]$ChartVersion = "0.29.0",
    [string]$CRDChartVersion = "0.5.0",
    [int]$TimeoutSeconds = 600
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

Require-Command "kubectl"
Require-Command "helm"

$projectRoot = Split-Path -Parent $PSScriptRoot
$valuesPath = Join-Path $projectRoot "deploy\spire\values.yaml"
$identitiesPath = Join-Path $projectRoot "deploy\spire\containgo-identities.yaml"
$repository = "https://spiffe.github.io/helm-charts-hardened/"

if (-not (Test-Path $valuesPath)) {
    throw "SPIRE values file not found: $valuesPath"
}

if (-not (Test-Path $identitiesPath)) {
    throw "ContainGo identity manifest not found: $identitiesPath"
}

$kubectlContextArguments = @()
$helmContextArguments = @()

if (-not [string]::IsNullOrWhiteSpace($KubeContext)) {
    $kubectlContextArguments = @("--context", $KubeContext)
    $helmContextArguments = @("--kube-context", $KubeContext)
}

$versionArguments = @()
if (-not [string]::IsNullOrWhiteSpace($ChartVersion)) {
    $versionArguments = @("--version", $ChartVersion)
}

$crdVersionArguments = @()
if (-not [string]::IsNullOrWhiteSpace($CRDChartVersion)) {
    $crdVersionArguments = @("--version", $CRDChartVersion)
}

Write-Host "Installing SPIRE CRDs..."
Invoke-Checked "helm" (@(
    "upgrade", "--install",
    "--create-namespace",
    "--namespace", $Namespace,
    "spire-crds", "spire-crds",
    "--repo", $repository
) + $crdVersionArguments + $helmContextArguments)

Write-Host "Installing the SPIRE hardened chart..."
Invoke-Checked "helm" (@(
    "upgrade", "--install",
    "--namespace", $Namespace,
    "spire", "spire",
    "--repo", $repository,
    "--values", $valuesPath,
    "--wait",
    "--timeout", "${TimeoutSeconds}s"
) + $versionArguments + $helmContextArguments)

Write-Host "Applying ContainGo ClusterSPIFFEID resources..."
Invoke-Checked "kubectl" ($kubectlContextArguments + @(
    "apply", "--filename", $identitiesPath
))

function Wait-ForNamespaceWorkloads {
    param(
        [string]$TargetNamespace
    )

    Write-Host (
        "Waiting for SPIRE workloads in namespace " +
        "'$TargetNamespace'..."
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $resources = @()

    do {
        $output = & kubectl `
            @kubectlContextArguments `
            --namespace $TargetNamespace `
            get deployments,statefulsets,daemonsets `
            --output name `
            2>$null

        if ($LASTEXITCODE -eq 0) {
            $resources = @(
                $output |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace($_)
                    }
            )
        }

        if ($resources.Count -gt 0) {
            break
        }

        Write-Host (
            "No rollout resources found in " +
            "'$TargetNamespace' yet; retrying..."
        )
        Start-Sleep -Seconds 5
    }
    while ((Get-Date) -lt $deadline)

    if ($resources.Count -eq 0) {
        kubectl `
            @kubectlContextArguments `
            get all `
            --namespace $TargetNamespace

        throw (
            "No SPIRE rollout resources appeared in " +
            "namespace '$TargetNamespace'."
        )
    }

    foreach ($resource in $resources) {
        Invoke-Checked "kubectl" (
            $kubectlContextArguments + @(
                "--namespace", $TargetNamespace,
                "rollout", "status",
                $resource,
                "--timeout=${TimeoutSeconds}s"
            )
        )
    }

    Write-Host (
        "SPIRE workloads are ready in " +
        "'$TargetNamespace'."
    )
}

Wait-ForNamespaceWorkloads -TargetNamespace "spire-server"
Wait-ForNamespaceWorkloads -TargetNamespace "spire-system"

Write-Host ""
Write-Host "SPIRE installation is ready."
Write-Host "Trust domain: containgo.local"
Write-Host "ContainGo namespace: containgo"
Write-Host ""
Write-Host "Run .\scripts\check-spire.ps1 to inspect the installation."
