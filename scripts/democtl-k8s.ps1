param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateSet(
        "status",
        "status-json",
        "inspect-json",
        "normal",
        "attack",
        "rapid",
        "pause",
        "release",
        "reset-risk"
    )]
    [string]$Command,

    [Parameter(Position = 1)]
    [string]$Workload = "report-client",

    [string]$ClusterName = "containgo"
)

$ErrorActionPreference = "Stop"
$context = "kind-$ClusterName"

$arguments = @($Command)

if ($Command -in @("release", "reset-risk", "inspect-json")) {
    $arguments += $Workload
}

kubectl `
    --context $context `
    --namespace containgo `
    exec `
    deployment/democtl `
    --container democtl `
    -- `
    /app/democtl `
    @arguments

if ($LASTEXITCODE -ne 0) {
    throw "democtl command failed."
}
