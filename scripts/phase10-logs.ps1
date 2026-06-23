param(
    [Parameter(Mandatory = $true)]
    [ValidateSet(
        "protected-api",
        "api-gateway",
        "control-plane",
        "order-client",
        "report-client",
        "dashboard",
        "democtl"
    )]
    [string]$Component,

    [string]$ClusterName = "containgo",
    [switch]$Follow
)

$ErrorActionPreference = "Stop"
$context = "kind-$ClusterName"

$arguments = @(
    "--context", $context,
    "--namespace", "containgo",
    "logs",
    "deployment/$Component",
    "--all-containers=true",
    "--tail=200"
)

if ($Follow) {
    $arguments += "--follow"
}

kubectl @arguments
