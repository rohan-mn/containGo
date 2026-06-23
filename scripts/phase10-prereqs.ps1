$ErrorActionPreference = "Stop"

$required = @("docker", "kind", "kubectl", "helm")

foreach ($command in $required) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required command '$command' was not found on PATH."
    }
}

Write-Host "Docker:"
docker version --format "  client={{.Client.Version}} server={{.Server.Version}}"

Write-Host "kind:"
kind version

Write-Host "kubectl:"
kubectl version --client

Write-Host "Helm:"
helm version --short

Write-Host ""
Write-Host "Phase 10 prerequisites are available."
