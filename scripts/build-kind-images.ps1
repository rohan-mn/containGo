param(
    [string]$ClusterName = "containgo",
    [switch]$NoCache
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot

$images = [ordered]@{
    "protected-api" = "build\docker\Dockerfile.protected-api"
    "api-gateway"   = "build\docker\Dockerfile.api-gateway"
    "control-plane" = "build\docker\Dockerfile.control-plane"
    "order-client"  = "build\docker\Dockerfile.order-client"
    "report-client" = "build\docker\Dockerfile.report-client"
    "dashboard"     = "build\docker\Dockerfile.dashboard"
    "democtl"       = "build\docker\Dockerfile.democtl"
}

foreach ($name in $images.Keys) {
    $dockerfile = Join-Path $projectRoot $images[$name]
    $tag = "containgo/${name}:dev"

    $arguments = @(
        "build",
        "--file", $dockerfile,
        "--tag", $tag
    )

    if ($NoCache) {
        $arguments += "--no-cache"
    }

    $arguments += $projectRoot

    Write-Host ""
    Write-Host "> docker $($arguments -join ' ')"
    docker @arguments

    if ($LASTEXITCODE -ne 0) {
        throw "Image build failed for $name."
    }
}

$imageTags = @(
    $images.Keys |
        ForEach-Object { "containgo/${_}:dev" }
)

Write-Host ""
Write-Host "Loading images into kind cluster '$ClusterName'..."

kind load docker-image `
    --name $ClusterName `
    @imageTags

if ($LASTEXITCODE -ne 0) {
    throw "kind image loading failed."
}

Write-Host ""
Write-Host "ContainGo images are available inside kind."
