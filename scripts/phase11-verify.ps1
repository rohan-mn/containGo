param(
    [string]$ClusterName = "containgo",
    [int]$TimeoutSeconds = 300,
    [switch]$ExerciseRecovery,
    [switch]$SkipNetworkIsolation
)

$ErrorActionPreference = "Stop"

$context = "kind-$ClusterName"
$namespace = "containgo"
$expectedDeployments = @(
    "api-gateway",
    "control-plane",
    "dashboard",
    "democtl",
    "order-client",
    "protected-api",
    "report-client"
)
$expectedPolicies = @(
    "allow-dns",
    "api-gateway-egress",
    "api-gateway-ingress",
    "control-plane-egress",
    "control-plane-ingress",
    "dashboard-traffic",
    "default-deny",
    "democtl-egress",
    "order-client-egress",
    "protected-api-ingress",
    "report-client-traffic"
)

function Require-Command {
    param([string]$Name)

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' was not found on PATH."
    }
}

function Assert-True {
    param(
        [bool]$Condition,
        [string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Invoke-Kubectl {
    param(
        [string[]]$Arguments,
        [switch]$Capture
    )

    if ($Capture) {
        $output = & kubectl @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "kubectl $($Arguments -join ' ') failed with code $LASTEXITCODE."
        }
        return $output
    }

    Write-Host "> kubectl $($Arguments -join ' ')"
    & kubectl @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "kubectl $($Arguments -join ' ') failed with code $LASTEXITCODE."
    }
}

function Get-KubeJSON {
    param([string[]]$Arguments)

    $raw = @(
        Invoke-Kubectl -Capture -Arguments ($Arguments + @("-o", "json"))
    ) -join "`n"

    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "kubectl returned empty JSON."
    }

    return $raw | ConvertFrom-Json
}

function Invoke-Demo {
    param([string[]]$Arguments)

    $kubectlArguments = @(
        "--context", $context,
        "--namespace", $namespace,
        "exec", "deployment/democtl",
        "--container", "democtl",
        "--",
        "/app/democtl"
    ) + $Arguments

    return Invoke-Kubectl -Capture -Arguments $kubectlArguments
}

function Get-DemoJSON {
    param([string[]]$Arguments)

    $raw = @(Invoke-Demo -Arguments $Arguments) -join "`n"
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "democtl returned empty JSON for '$($Arguments -join ' ')'."
    }

    try {
        return $raw | ConvertFrom-Json
    }
    catch {
        Write-Host "Raw democtl output:"
        Write-Host $raw
        throw
    }
}

function Get-Workload {
    param(
        [object]$Status,
        [string]$Name
    )

    $matches = @(
        $Status.workloads |
            Where-Object { $_.name -eq $Name }
    )

    if ($matches.Count -ne 1) {
        throw "Expected exactly one workload named '$Name', found $($matches.Count)."
    }

    return $matches[0]
}

function Wait-DemoState {
    param(
        [string]$Description,
        [scriptblock]$Predicate
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastStatus = $null

    do {
        $lastStatus = Get-DemoJSON -Arguments @("status-json")
        if (& $Predicate $lastStatus) {
            Write-Host "Verified: $Description"
            return $lastStatus
        }

        Start-Sleep -Seconds 2
    }
    while ((Get-Date) -lt $deadline)

    Write-Host "Last observed status:"
    $lastStatus | ConvertTo-Json -Depth 8
    throw "Timed out waiting for: $Description"
}

function Test-TCPFromDemoctl {
    param(
        [string]$HostName,
        [int]$Port,
        [bool]$ShouldSucceed
    )

    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"

    & kubectl `
        --context $context `
        --namespace $namespace `
        exec deployment/democtl `
        --container democtl `
        -- `
        /bin/sh -c "nc -z -w 4 $HostName $Port" `
        *> $null

    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $previousPreference

    if ($ShouldSucceed -and $exitCode -ne 0) {
        throw "Expected TCP access from democtl to ${HostName}:$Port, but it failed."
    }

    if (-not $ShouldSucceed -and $exitCode -eq 0) {
        throw "Expected NetworkPolicy to block democtl from ${HostName}:$Port, but it connected."
    }
}

Require-Command "kubectl"

Write-Host "=== 1. Kubernetes rollout and storage checks ==="
foreach ($deployment in $expectedDeployments) {
    Invoke-Kubectl -Arguments @(
        "--context", $context,
        "--namespace", $namespace,
        "rollout", "status",
        "deployment/$deployment",
        "--timeout=${TimeoutSeconds}s"
    )
}

$deployments = Get-KubeJSON -Arguments @(
    "--context", $context,
    "--namespace", $namespace,
    "get", "deployments"
)

$deploymentNames = @($deployments.items | ForEach-Object { $_.metadata.name })
foreach ($expected in $expectedDeployments) {
    Assert-True ($deploymentNames -contains $expected) "Missing deployment '$expected'."
}

$pvc = Get-KubeJSON -Arguments @(
    "--context", $context,
    "--namespace", $namespace,
    "get", "pvc/containgo-sqlite"
)
Assert-True ($pvc.status.phase -eq "Bound") "SQLite PVC is not Bound."

Write-Host "=== 2. Pod health and restart checks ==="
$pods = Get-KubeJSON -Arguments @(
    "--context", $context,
    "--namespace", $namespace,
    "get", "pods"
)

foreach ($pod in @($pods.items)) {
    Assert-True ($pod.status.phase -eq "Running") "Pod '$($pod.metadata.name)' is not Running."

    foreach ($containerStatus in @($pod.status.containerStatuses)) {
        Assert-True $containerStatus.ready "Container '$($containerStatus.name)' in '$($pod.metadata.name)' is not ready."
        Assert-True ($containerStatus.restartCount -eq 0) "Container '$($containerStatus.name)' in '$($pod.metadata.name)' has $($containerStatus.restartCount) restarts."
    }
}

Write-Host "=== 3. SPIFFE registration checks ==="

$expectedIdentityCount = $expectedDeployments.Count
$registrationDeadline = (Get-Date).AddSeconds(
    $TimeoutSeconds
)

$registration = $null
$registrationReady = $false

do {
    $registration = Get-KubeJSON -Arguments @(
        "--context", $context,
        "get", "clusterspiffeid/containgo-workloads"
    )

    Assert-True `
        ($registration.spec.className -eq "containgo") `
        "Unexpected ClusterSPIFFEID className."

    $stats = $registration.status.stats

    $entriesToSet = [int]$stats.entriesToSet
    $entryFailures = [int]$stats.entryFailures
    $podsSelected = [int]$stats.podsSelected
    $renderFailures = [int]$stats.podEntryRenderFailures

    $registrationReady = (
        $entriesToSet -eq $expectedIdentityCount -and
        $podsSelected -eq $expectedIdentityCount -and
        $entryFailures -eq 0 -and
        $renderFailures -eq 0
    )

    if ($registrationReady) {
        break
    }

    Write-Host (
        "Waiting for SPIRE registration to converge: " +
        "entriesToSet=$entriesToSet, " +
        "podsSelected=$podsSelected, " +
        "entryFailures=$entryFailures, " +
        "renderFailures=$renderFailures"
    )

    Start-Sleep -Seconds 2
}
while ((Get-Date) -lt $registrationDeadline)

if (-not $registrationReady) {
    Write-Host ""
    Write-Host "Last ClusterSPIFFEID status:"

    $registration.status |
        ConvertTo-Json -Depth 8 |
        Out-Host

    throw (
        "SPIRE registration did not converge to " +
        "$expectedIdentityCount workload entries."
    )
}

Write-Host (
    "Verified: SPIRE rendered $expectedIdentityCount " +
    "workload entries without failures."
)

Write-Host "=== 4. Kubernetes workload-hardening checks ==="
foreach ($deployment in @($deployments.items)) {
    $name = $deployment.metadata.name
    $podSpec = $deployment.spec.template.spec
    $labels = $deployment.spec.template.metadata.labels

    Assert-True ($podSpec.automountServiceAccountToken -eq $false) "$name mounts a Kubernetes ServiceAccount token."
    Assert-True ($podSpec.securityContext.runAsNonRoot -eq $true) "$name does not enforce runAsNonRoot."
    Assert-True ($podSpec.securityContext.seccompProfile.type -eq "RuntimeDefault") "$name does not use RuntimeDefault seccomp."
    Assert-True ($labels.'containgo.io/spiffe' -eq "true") "$name is missing the SPIFFE selection label."

    $spiffeVolumes = @(
        $podSpec.volumes |
            Where-Object {
                $_.name -eq "spiffe-workload-api" -and
                $_.csi.driver -eq "csi.spiffe.io"
            }
    )
    Assert-True ($spiffeVolumes.Count -eq 1) "$name is missing the SPIFFE CSI volume."

    foreach ($container in @($podSpec.containers)) {
        $security = $container.securityContext
        Assert-True ($security.allowPrivilegeEscalation -eq $false) "$name/$($container.name) allows privilege escalation."
        Assert-True ($security.readOnlyRootFilesystem -eq $true) "$name/$($container.name) does not use a read-only root filesystem."
        Assert-True (@($security.capabilities.drop) -contains "ALL") "$name/$($container.name) does not drop all Linux capabilities."
    }
}

Write-Host "=== 5. NetworkPolicy checks ==="
$policies = Get-KubeJSON -Arguments @(
    "--context", $context,
    "--namespace", $namespace,
    "get", "networkpolicies"
)
$policyNames = @($policies.items | ForEach-Object { $_.metadata.name })
foreach ($policy in $expectedPolicies) {
    Assert-True ($policyNames -contains $policy) "Missing NetworkPolicy '$policy'."
}

if (-not $SkipNetworkIsolation) {
    Test-TCPFromDemoctl `
        -HostName "control-plane.containgo.svc.cluster.local" `
        -Port 8090 `
        -ShouldSucceed $true

    Test-TCPFromDemoctl `
        -HostName "report-client.containgo.svc.cluster.local" `
        -Port 8072 `
        -ShouldSucceed $true

    Test-TCPFromDemoctl `
        -HostName "protected-api.containgo.svc.cluster.local" `
        -Port 8080 `
        -ShouldSucceed $false

    Write-Host "Verified: allowed paths connect and the forbidden direct path is blocked."
}

Write-Host "=== 6. Normalize the demo state ==="
$status = Get-DemoJSON -Arguments @("status-json")
$report = Get-Workload -Status $status -Name "report-client"

if ($status.report_client.mode -ne "normal") {
    @(Invoke-Demo -Arguments @("normal")) | Out-Host
}

if ($report.status -eq "quarantined") {
    @(Invoke-Demo -Arguments @("release", "report-client")) | Out-Host
}
elseif ($report.risk_score -gt 0) {
    @(Invoke-Demo -Arguments @("reset-risk", "report-client")) | Out-Host
}

Invoke-Kubectl -Arguments @(
    "--context", $context,
    "--namespace", $namespace,
    "rollout", "restart",
    "deployment/report-client"
)
Invoke-Kubectl -Arguments @(
    "--context", $context,
    "--namespace", $namespace,
    "rollout", "status",
    "deployment/report-client",
    "--timeout=${TimeoutSeconds}s"
)

$status = Wait-DemoState -Description "normal Report Client traffic succeeds without failures" -Predicate {
    param($value)
    $workload = Get-Workload -Status $value -Name "report-client"
    return (
        $workload.status -eq "active" -and
        $workload.risk_score -eq 0 -and
        $value.report_client.mode -eq "normal" -and
        $value.report_client.successful_requests -ge 2 -and
        $value.report_client.failed_requests -eq 0 -and
        $value.report_client.last_status -eq 200
    )
}

Write-Host "=== 7. Exercise automatic quarantine ==="
@(Invoke-Demo -Arguments @("attack")) | Out-Host

$attackStatus = Wait-DemoState -Description "Report Client is automatically quarantined while Order Client stays active" -Predicate {
    param($value)
    $reportWorkload = Get-Workload -Status $value -Name "report-client"
    $orderWorkload = Get-Workload -Status $value -Name "order-client"
    return (
        $reportWorkload.status -eq "quarantined" -and
        $reportWorkload.risk_score -ge 70 -and
        $reportWorkload.denied_requests -gt 0 -and
        $orderWorkload.status -eq "active" -and
        $orderWorkload.risk_score -eq 0 -and
        $value.report_client.forbidden_requests -gt 0 -and
        $value.report_client.last_status -eq 403
    )
}

$attackReport = Get-Workload -Status $attackStatus -Name "report-client"
$inspect = Get-DemoJSON -Arguments @("inspect-json", "report-client")
$openIncidents = @(
    $inspect.incidents |
        Where-Object { $_.status -eq "open" } |
        Sort-Object id -Descending
)
Assert-True ($openIncidents.Count -ge 1) "No open incident was created."

$incident = $openIncidents[0]
$reasonPoints = [int](
    ($incident.reasons | Measure-Object -Property points -Sum).Sum
)
Assert-True ($reasonPoints -eq $incident.score_at_quarantine) "Incident reason points ($reasonPoints) do not equal score at quarantine ($($incident.score_at_quarantine))."
Assert-True ($incident.score_at_quarantine -eq $attackReport.risk_score) "Incident score and workload score differ."
Write-Host "Verified: the incident contains complete evidence totaling $reasonPoints points."

Write-Host "=== 8. Exercise release and audit preservation ==="
@(Invoke-Demo -Arguments @("normal")) | Out-Host
@(Invoke-Demo -Arguments @("release", "report-client")) | Out-Host

$releasedStatus = Wait-DemoState -Description "released Report Client returns to normal allowed traffic" -Predicate {
    param($value)
    $workload = Get-Workload -Status $value -Name "report-client"
    return (
        $workload.status -eq "active" -and
        $workload.risk_score -eq 0 -and
        $workload.denied_requests -eq 0 -and
        $value.report_client.mode -eq "normal" -and
        $value.report_client.last_status -eq 200
    )
}

$inspect = Get-DemoJSON -Arguments @("inspect-json", "report-client")
$releasedIncident = @(
    $inspect.incidents |
        Where-Object { $_.id -eq $incident.id }
)[0]
Assert-True ($null -ne $releasedIncident) "The released incident disappeared from history."
Assert-True ($releasedIncident.status -eq "released") "Incident status is not released."

$auditActions = @($inspect.audit_records | ForEach-Object { $_.action })
foreach ($action in @(
    "incident_released",
    "workload_released",
    "opa_quarantine_removed"
)) {
    Assert-True ($auditActions -contains $action) "Missing audit action '$action'."
}

if ($ExerciseRecovery) {
    Write-Host "=== 9. Exercise Kubernetes recovery ==="
    foreach ($deployment in @(
        "api-gateway",
        "control-plane"
    )) {
        Invoke-Kubectl -Arguments @(
            "--context", $context,
            "--namespace", $namespace,
            "rollout", "restart",
            "deployment/$deployment"
        )

        Invoke-Kubectl -Arguments @(
            "--context", $context,
            "--namespace", $namespace,
            "rollout", "status",
            "deployment/$deployment",
            "--timeout=${TimeoutSeconds}s"
        )
    }

    Wait-DemoState -Description "normal traffic recovers after Gateway and Control Plane restarts" -Predicate {
        param($value)
        $reportWorkload = Get-Workload -Status $value -Name "report-client"
        $orderWorkload = Get-Workload -Status $value -Name "order-client"
        return (
            $reportWorkload.status -eq "active" -and
            $orderWorkload.status -eq "active" -and
            $value.report_client.last_status -eq 200
        )
    } | Out-Null
}

Write-Host ""
Write-Host "============================================================"
Write-Host "ContainGo Phase 11 verification PASSED"
Write-Host "============================================================"
Write-Host "Verified:"
Write-Host "  - Seven healthy SPIFFE-enabled workloads"
Write-Host "  - SQLite persistence"
Write-Host "  - Pod and container hardening"
Write-Host "  - NetworkPolicy allow and deny paths"
Write-Host "  - Normal request flow"
Write-Host "  - OPA denial and automatic quarantine"
Write-Host "  - Complete incident evidence"
Write-Host "  - Release, risk reset, and audit preservation"
if ($ExerciseRecovery) {
    Write-Host "  - Kubernetes restart recovery"
}
