param(
    [string]$KubeContext = "",
    [string]$Namespace = "spire"
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command kubectl -ErrorAction SilentlyContinue)) {
    throw "Required command 'kubectl' was not found on PATH."
}

$contextArguments = @()
if (-not [string]::IsNullOrWhiteSpace($KubeContext)) {
    $contextArguments = @("--context", $KubeContext)
}

function Run-Kubectl {
    param([string[]]$Arguments)

    Write-Host ""
    Write-Host "> kubectl $($Arguments -join ' ')"
    & kubectl @contextArguments @Arguments

    if ($LASTEXITCODE -ne 0) {
        throw "kubectl exited with code $LASTEXITCODE."
    }
}

Run-Kubectl @("get", "pods", "--namespace", $Namespace, "--output", "wide")
Run-Kubectl @("get", "csidriver", "csi.spiffe.io")
Run-Kubectl @("get", "clusterspiffeid", "containgo-workloads", "--output", "yaml")
Run-Kubectl @("get", "namespace", "containgo", "--show-labels")

Write-Host ""
Write-Host "SPIRE verification completed."
