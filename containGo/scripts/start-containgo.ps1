[CmdletBinding()]
param(
    [string]$ClusterName = 'containgo',
    [int]$DashboardPort = 8060,
    [switch]$Repair,
    [switch]$RebuildImages,
    [switch]$NoBrowser,
    [switch]$SkipSmokeTest
)

$RepositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'lib\Common.ps1')
Require-Windows
Set-Location $RepositoryRoot

$StateDirectory = Join-Path $RepositoryRoot '.containgo'
$LogDirectory = Join-Path $StateDirectory 'logs'
$ToolDirectory = Join-Path $StateDirectory 'tools'
New-Item -ItemType Directory -Force -Path $LogDirectory,$ToolDirectory | Out-Null
$RunLog = Join-Path $LogDirectory ("start-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$Context = "kind-$ClusterName"
$NodeContainer = "$ClusterName-control-plane"
$PortPidFile = Join-Path $StateDirectory 'dashboard-port-forward.pid'
$PortLog = Join-Path $LogDirectory 'dashboard-port-forward.log'
$AgentIDStateFile = Join-Path $StateDirectory 'spire-agent-id.txt'
$AgentIDPrefix = "spiffe://containgo.local/spire/agent/join_token/"
$LegacyAgentAlias = "spiffe://containgo.local/kind/$ClusterName-control-plane"
$NodeSPIFFEID = $null

function Kube {
    [CmdletBinding(PositionalBinding=$false)]
    param([Parameter(Mandatory=$true)][string[]]$KubeArgs)
    $arguments = @('--context',$Context) + $KubeArgs
    Invoke-Native -File 'kubectl' -Arguments $arguments -LogFile $RunLog
}

function Wait-DeploymentAbsent {
    [CmdletBinding(PositionalBinding=$false)]
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [int]$WaitSeconds = 45
    )

    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    while ((Get-Date) -lt $deadline) {
        $check = Invoke-NativeCapture -File 'kubectl' -Arguments @(
            '--context',$Context,'get','deployment',$Name,'-n','containgo','-o','json'
        ) -AllowFailure -LogFile $RunLog

        if ($check.ExitCode -ne 0 -and $check.Output -match '(?i)(NotFound|not found)') {
            return $true
        }

        if ($check.ExitCode -eq 0) {
            try {
                $deployment = $check.StdOut | ConvertFrom-Json -ErrorAction Stop
                $deletionProperty = $deployment.metadata.PSObject.Properties['deletionTimestamp']
                $finalizersProperty = $deployment.metadata.PSObject.Properties['finalizers']
                $hasDeletionTimestamp = $null -ne $deletionProperty -and -not [string]::IsNullOrWhiteSpace([string]$deletionProperty.Value)
                $hasFinalizers = $null -ne $finalizersProperty -and @($finalizersProperty.Value).Count -gt 0
                if ($hasDeletionTimestamp -and $hasFinalizers) {
                    # A previous foreground deletion may leave the Deployment
                    # waiting for ReplicaSets or Pods forever. The Deployment
                    # contains no persistent data, so clear only its deletion
                    # finalizer. Services, PVCs and SPIRE state are unaffected.
                    $patch = '{"metadata":{"finalizers":[]}}'
                    Invoke-NativeCapture -File 'kubectl' -Arguments @(
                        '--context',$Context,'patch','deployment',$Name,'-n','containgo',
                        '--type=merge','-p',$patch
                    ) -AllowFailure -LogFile $RunLog | Out-Null
                }
            } catch {
                # Continue polling. A short partial response while the API
                # object is disappearing must not make recovery fail.
            }
        }

        Start-Sleep -Seconds 1
    }
    return $false
}

function Wait-LegacyPodsAbsent {
    [CmdletBinding(PositionalBinding=$false)]
    param(
        [Parameter(Mandatory=$true)][string]$LabelSelector,
        [int]$WaitSeconds = 60
    )

    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    while ((Get-Date) -lt $deadline) {
        $pods = Invoke-NativeCapture -File 'kubectl' -Arguments @(
            '--context',$Context,'get','pods','-n','containgo','-l',$LabelSelector,'-o','name'
        ) -AllowFailure -LogFile $RunLog
        if ($pods.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($pods.StdOut)) {
            return $true
        }
        Start-Sleep -Seconds 1
    }
    return $false
}

function Remove-IncompatibleApplicationDeployments {
    [CmdletBinding(PositionalBinding=$false)]
    param([Parameter(Mandatory=$true)][string[]]$Names)

    # apps/v1 Deployment selectors are immutable. Earlier ContainGo releases
    # used a different selector. Delete only the incompatible controller and
    # its old ReplicaSets/Pods. Services, PVCs, ConfigMaps, SPIRE state and
    # persisted Control Plane data remain untouched.
    foreach ($name in $Names) {
        $existing = Invoke-NativeCapture -File 'kubectl' -Arguments @(
            '--context',$Context,'get','deployment',$name,'-n','containgo','-o','json'
        ) -AllowFailure -LogFile $RunLog

        if ($existing.ExitCode -ne 0) {
            if ($existing.Output -match '(?i)(NotFound|not found)') {
                # A previous failed migration may have removed the Deployment
                # object but left an orphaned old ReplicaSet or Pod. Because the
                # new Deployment has not been applied yet, both historical
                # selectors can be cleaned safely here.
                foreach ($staleSelector in @("app.kubernetes.io/name=$name","app=$name")) {
                    Invoke-NativeCapture -File 'kubectl' -Arguments @(
                        '--context',$Context,'delete','replicaset','-n','containgo','-l',$staleSelector,
                        '--cascade=background','--wait=false','--ignore-not-found=true'
                    ) -AllowFailure -LogFile $RunLog | Out-Null
                    Invoke-NativeCapture -File 'kubectl' -Arguments @(
                        '--context',$Context,'delete','pod','-n','containgo','-l',$staleSelector,
                        '--wait=false','--ignore-not-found=true'
                    ) -AllowFailure -LogFile $RunLog | Out-Null
                }
                continue
            }
            throw "Unable to inspect existing Deployment '$name'.`n$($existing.Output)"
        }

        try {
            $deployment = $existing.StdOut | ConvertFrom-Json -ErrorAction Stop
        } catch {
            throw "kubectl returned invalid JSON while inspecting Deployment '$name'.`n$($existing.Output)"
        }

        $selectorProperties = @($deployment.spec.selector.matchLabels.PSObject.Properties)
        $selectorIsCompatible = $selectorProperties.Count -eq 1 -and
            $selectorProperties[0].Name -eq 'app' -and
            [string]$selectorProperties[0].Value -eq $name

        $deletionProperty = $deployment.metadata.PSObject.Properties['deletionTimestamp']
        $deletionTimestamp = if ($null -ne $deletionProperty) { [string]$deletionProperty.Value } else { $null }
        if ($selectorIsCompatible -and [string]::IsNullOrWhiteSpace($deletionTimestamp)) { continue }

        $selectorDescription = if ($selectorProperties.Count -gt 0) {
            ($selectorProperties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ', '
        } else {
            '<empty>'
        }
        $oldLabelSelector = if ($selectorProperties.Count -gt 0) {
            ($selectorProperties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ','
        } else {
            "app=$name"
        }

        if (-not [string]::IsNullOrWhiteSpace($deletionTimestamp)) {
            Write-Warn "Deployment '$name' is left in a terminating state by an earlier migration; completing that deletion safely."
        } else {
            Write-Warn "Deployment '$name' uses immutable selector {$selectorDescription}; recreating only this Deployment with selector {app=$name}."
        }

        # Do not use foreground cascading here. Foreground deletion adds a
        # finalizer and waits for every dependent Pod, which is exactly what
        # caused the previous migration attempt to time out. Orphan the dependants, remove the Deployment
        # object, then explicitly delete the old ReplicaSet/Pods by the old
        # immutable selector before applying the new controller.
        $delete = Invoke-NativeCapture -File 'kubectl' -Arguments @(
            '--context',$Context,'delete','deployment',$name,'-n','containgo',
            '--cascade=orphan','--wait=false','--ignore-not-found=true'
        ) -AllowFailure -LogFile $RunLog
        if ($delete.Output) { Write-Host $delete.Output }
        if ($delete.ExitCode -ne 0 -and $delete.Output -notmatch '(?i)(NotFound|not found)') {
            throw "Unable to start deletion of incompatible Deployment '$name'.`n$($delete.Output)"
        }

        if (-not (Wait-DeploymentAbsent -Name $name -WaitSeconds 45)) {
            # Last-resort recovery for an object already carrying Kubernetes'
            # foregroundDeletion finalizer from a previous failed run.
            $patch = '{"metadata":{"finalizers":[]}}'
            Invoke-NativeCapture -File 'kubectl' -Arguments @(
                '--context',$Context,'patch','deployment',$name,'-n','containgo',
                '--type=merge','-p',$patch
            ) -AllowFailure -LogFile $RunLog | Out-Null
            Invoke-NativeCapture -File 'kubectl' -Arguments @(
                '--context',$Context,'delete','deployment',$name,'-n','containgo',
                '--cascade=orphan','--wait=false','--ignore-not-found=true'
            ) -AllowFailure -LogFile $RunLog | Out-Null
            if (-not (Wait-DeploymentAbsent -Name $name -WaitSeconds 20)) {
                throw "Deployment '$name' is still present after clearing its deletion finalizer. Inspect metadata.finalizers in the diagnostics log."
            }
        }

        $replicaSets = Invoke-NativeCapture -File 'kubectl' -Arguments @(
            '--context',$Context,'delete','replicaset','-n','containgo','-l',$oldLabelSelector,
            '--cascade=background','--wait=false','--ignore-not-found=true'
        ) -AllowFailure -LogFile $RunLog
        if ($replicaSets.Output) { Write-Host $replicaSets.Output }
        if ($replicaSets.ExitCode -ne 0 -and $replicaSets.Output -notmatch '(?i)(No resources found|NotFound|not found)') {
            throw "Unable to remove the old ReplicaSet for Deployment '$name'.`n$($replicaSets.Output)"
        }

        $pods = Invoke-NativeCapture -File 'kubectl' -Arguments @(
            '--context',$Context,'delete','pod','-n','containgo','-l',$oldLabelSelector,
            '--wait=false','--ignore-not-found=true'
        ) -AllowFailure -LogFile $RunLog
        if ($pods.Output) { Write-Host $pods.Output }

        if (-not (Wait-LegacyPodsAbsent -LabelSelector $oldLabelSelector -WaitSeconds 60)) {
            Write-Warn "Old Pods for '$name' did not terminate normally; force-removing only Pods selected by '$oldLabelSelector'."
            Invoke-NativeCapture -File 'kubectl' -Arguments @(
                '--context',$Context,'delete','pod','-n','containgo','-l',$oldLabelSelector,
                '--grace-period=0','--force','--wait=false','--ignore-not-found=true'
            ) -AllowFailure -LogFile $RunLog | Out-Null
            if (-not (Wait-LegacyPodsAbsent -LabelSelector $oldLabelSelector -WaitSeconds 20)) {
                throw "Old Pods for Deployment '$name' are still present after force deletion."
            }
        }

        Write-Ok "Removed incompatible Deployment '$name' and its old ReplicaSet/Pods; persistent resources were preserved."
    }
}

function New-ContainGoCluster {
    Write-Host "Creating kind cluster '$ClusterName'."
    Invoke-Native -File 'kind' -Arguments @('create','cluster','--name',$ClusterName,'--config',(Join-Path $RepositoryRoot 'deploy\kind\config.yaml'),'--image','kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5') -LogFile $RunLog
}
function Remove-ContainGoCluster([string]$Reason) {
    if ($Reason) { Write-Warn $Reason }
    $delete = Invoke-NativeCapture -File 'kind' -Arguments @('delete','cluster','--name',$ClusterName) -AllowFailure -LogFile $RunLog
    $leftoverNode = Invoke-NativeCapture -File 'docker' -Arguments @('inspect',$NodeContainer) -AllowFailure
    if ($leftoverNode.ExitCode -eq 0) {
        Write-Warn "kind did not remove the stale node container; force-removing '$NodeContainer'."
        Invoke-Native -File 'docker' -Arguments @('rm','-f',$NodeContainer) -AllowFailure -LogFile $RunLog
    }

    # Remove stale kubeconfig records as well. A partially deleted or previously
    # restored kind cluster can otherwise leave a context that points at an old
    # certificate authority or an identity with broken RBAC bindings.
    Invoke-NativeCapture -File 'kubectl' -Arguments @('config','delete-context',$Context) -AllowFailure -LogFile $RunLog | Out-Null
    Invoke-NativeCapture -File 'kubectl' -Arguments @('config','delete-cluster',$Context) -AllowFailure -LogFile $RunLog | Out-Null
    Invoke-NativeCapture -File 'kubectl' -Arguments @('config','delete-user',$Context) -AllowFailure -LogFile $RunLog | Out-Null
}
function Export-ContainGoKubeconfig {
    $export = Invoke-NativeCapture -File 'kind' -Arguments @('export','kubeconfig','--name',$ClusterName) -LogFile $RunLog
    # kind prints "Set kubectl context ..." on STDERR even after a successful
    # export. Invoke-NativeCapture deliberately evaluates the exit code instead
    # of treating that informational line as a PowerShell exception.
    if ($export.ExitCode -ne 0) { throw "Unable to export kubeconfig for '$ClusterName'." }
}
function Get-KubernetesClusterHealth([int]$WaitSeconds = 90) {
    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    $lastOutput = 'The Kubernetes API has not answered yet.'

    while ((Get-Date) -lt $deadline) {
        $ready = Invoke-NativeCapture -File 'kubectl' -Arguments @('--context',$Context,'get','--raw=/readyz') -AllowFailure
        if ($ready.ExitCode -eq 0) {
            $authorization = Invoke-NativeCapture -File 'kubectl' -Arguments @('--context',$Context,'auth','can-i','list','pods','--all-namespaces') -AllowFailure
            if ($authorization.ExitCode -ne 0 -or $authorization.Output -notmatch '(?im)^\s*yes\s*$') {
                return [pscustomobject]@{
                    Healthy = $false
                    Reason  = "The Kubernetes API is reachable, but the exported kind administrator cannot list pods across namespaces. The old cluster RBAC or kubeconfig is corrupted. kubectl auth can-i returned: $($authorization.Output)"
                }
            }

            $nodes = Invoke-NativeCapture -File 'kubectl' -Arguments @('--context',$Context,'get','nodes','-o','name') -AllowFailure
            if ($nodes.ExitCode -eq 0 -and $nodes.Output -match 'node/') {
                return [pscustomobject]@{ Healthy = $true; Reason = 'Kubernetes API and administrator RBAC are healthy.' }
            }
            $lastOutput = $nodes.Output
        } else {
            $lastOutput = $ready.Output
        }
        Start-Sleep -Seconds 2
    }

    return [pscustomobject]@{
        Healthy = $false
        Reason  = "The Kubernetes API did not become usable within $WaitSeconds seconds. Last response: $lastOutput"
    }
}
function Initialize-AndValidateCluster {
    Export-ContainGoKubeconfig
    return Get-KubernetesClusterHealth -WaitSeconds 90
}
function Set-CurrentAgentID {
    param([Parameter(Mandatory=$true)][string]$SPIFFEID)
    if ($SPIFFEID -notmatch '^spiffe://containgo\.local/spire/agent/join_token/[^/]+$') {
        throw "Refusing invalid join-token Agent SPIFFE ID: $SPIFFEID"
    }
    $script:NodeSPIFFEID = $SPIFFEID
    Set-Content -Path $AgentIDStateFile -Value $SPIFFEID
}
function Get-AgentIDFromJoinToken {
    param([Parameter(Mandatory=$true)][string]$Token)
    $cleanToken = $Token.Trim()
    if ([string]::IsNullOrWhiteSpace($cleanToken)) { return $null }
    return "$AgentIDPrefix$cleanToken"
}
function Get-JoinTokenFromSecret {
    $tokenResult = Invoke-NativeCapture -File 'kubectl' -Arguments @('--context',$Context,'get','secret','spire-agent-join-token','-n','spire','-o','jsonpath={.data.token}') -AllowFailure -LogFile $RunLog
    if ($tokenResult.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($tokenResult.StdOut)) { return $null }
    try {
        return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($tokenResult.StdOut.Trim())).Trim()
    } catch {
        Write-Warn "The existing SPIRE join-token Secret contains invalid base64 data and will be rebuilt."
        return $null
    }
}
function Test-SpireAgentRecord {
    param([Parameter(Mandatory=$true)][string]$SPIFFEID)
    $agent = Invoke-NativeCapture -File 'kubectl' -Arguments @('--context',$Context,'exec','-n','spire','deploy/spire-server','--','/opt/spire/bin/spire-server','agent','show','-socketPath','/run/spire/sockets/server.sock','-spiffeID',$SPIFFEID) -AllowFailure -LogFile $RunLog
    return $agent.ExitCode -eq 0 -and $agent.Output -match [regex]::Escape($SPIFFEID)
}
function Get-JoinTokenAgentIDs {
    $agents = Invoke-NativeCapture -File 'kubectl' -Arguments @('--context',$Context,'exec','-n','spire','deploy/spire-server','--','/opt/spire/bin/spire-server','agent','list','-socketPath','/run/spire/sockets/server.sock','-attestationType','join_token') -AllowFailure -LogFile $RunLog
    if ($agents.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($agents.Output)) { return @() }
    $matches = [regex]::Matches($agents.Output, '(?im)^\s*SPIFFE ID\s*:\s*(spiffe://\S+)\s*$')
    return @($matches | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
}
function Remove-SpireEntriesBySPIFFEID {
    param([Parameter(Mandatory=$true)][string]$SPIFFEID)
    $show = Invoke-NativeCapture -File 'kubectl' -Arguments @('--context',$Context,'exec','-n','spire','deploy/spire-server','--','/opt/spire/bin/spire-server','entry','show','-socketPath','/run/spire/sockets/server.sock','-spiffeID',$SPIFFEID) -AllowFailure -LogFile $RunLog
    if ($show.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($show.Output)) { return }
    $entryMatches = [regex]::Matches($show.Output, '(?im)^\s*Entry ID\s*:\s*(\S+)\s*$')
    foreach ($match in $entryMatches) {
        Invoke-Native -File 'kubectl' -Arguments @('--context',$Context,'exec','-n','spire','deploy/spire-server','--','/opt/spire/bin/spire-server','entry','delete','-socketPath','/run/spire/sockets/server.sock','-entryID',$match.Groups[1].Value) -AllowFailure -LogFile $RunLog
    }
}
function New-AgentJoinToken {
    # Do not pass -spiffeID here. For join-token attestation SPIRE itself assigns
    # the Agent ID as spiffe://<trust-domain>/spire/agent/join_token/<token>.
    # The -spiffeID flag creates a workload alias beneath that Agent; it does
    # not rename the Agent and therefore must not be used as the parent ID.
    $tokenResult = Invoke-NativeCapture -File 'kubectl' -Arguments @('--context',$Context,'exec','-n','spire','deploy/spire-server','--','/opt/spire/bin/spire-server','token','generate','-socketPath','/run/spire/sockets/server.sock','-ttl','900') -AllowFailure -LogFile $RunLog
    if ($tokenResult.ExitCode -ne 0 -or $tokenResult.Output -notmatch 'Token:\s*(\S+)') {
        throw "Unable to generate a SPIRE Agent join token.`n$($tokenResult.Output)"
    }
    $joinToken = $Matches[1].Trim()
    $agentID = Get-AgentIDFromJoinToken -Token $joinToken
    Set-CurrentAgentID -SPIFFEID $agentID

    $tokenManifest = Invoke-NativeCapture -File 'kubectl' -Arguments @('--context',$Context,'create','secret','generic','spire-agent-join-token','-n','spire',"--from-literal=token=$joinToken","--from-literal=agent-id=$agentID",'--dry-run=client','-o','yaml') -LogFile $RunLog
    $applyResult = Invoke-NativeWithInput -File 'kubectl' -Arguments @('--context',$Context,'apply','-f','-') -InputText $tokenManifest.StdOut -LogFile $RunLog
    if ($applyResult.Output) { Write-Host $applyResult.Output }
    Write-Ok "Generated a one-time SPIRE join token for Agent $agentID."
}
function Resolve-CurrentAgentID {
    $joinToken = Get-JoinTokenFromSecret
    if ($joinToken) {
        $candidate = Get-AgentIDFromJoinToken -Token $joinToken
        Set-CurrentAgentID -SPIFFEID $candidate
        return $candidate
    }

    if (Test-Path $AgentIDStateFile) {
        $candidate = (Get-Content $AgentIDStateFile -Raw).Trim()
        if ($candidate -and (Test-SpireAgentRecord -SPIFFEID $candidate)) {
            Set-CurrentAgentID -SPIFFEID $candidate
            return $candidate
        }
    }
    return $null
}
function Repair-SpireAgent {
    Write-Warn 'SPIRE Agent attestation is stale or unavailable; rebuilding its local attestation state.'
    Invoke-Native -File 'kubectl' -Arguments @('--context',$Context,'delete','daemonset','spire-agent','-n','spire','--ignore-not-found','--wait=true','--timeout=120s') -AllowFailure -LogFile $RunLog

    # Evict every join-token Agent left by an interrupted earlier run. The
    # active Agent ID is token-derived, so a fixed human-readable ID is invalid.
    $candidateIDs = @()
    if ($script:NodeSPIFFEID) { $candidateIDs += $script:NodeSPIFFEID }
    $candidateIDs += @(Get-JoinTokenAgentIDs)
    foreach ($candidateID in @($candidateIDs | Where-Object { $_ } | Sort-Object -Unique)) {
        Invoke-Native -File 'kubectl' -Arguments @('--context',$Context,'exec','-n','spire','deploy/spire-server','--','/opt/spire/bin/spire-server','agent','evict','-socketPath','/run/spire/sockets/server.sock','-spiffeID',$candidateID) -AllowFailure -LogFile $RunLog
    }

    # Remove alias entries created by V4's incorrect use of token generate
    # -spiffeID. Workload entries are parented directly to the real Agent.
    Remove-SpireEntriesBySPIFFEID -SPIFFEID $LegacyAgentAlias

    Invoke-Native -File 'docker' -Arguments @('exec',$NodeContainer,'sh','-c','rm -rf /run/spire/data/* /run/spire/sockets/*') -AllowFailure -LogFile $RunLog
    Invoke-Native -File 'kubectl' -Arguments @('--context',$Context,'delete','secret','spire-agent-join-token','-n','spire','--ignore-not-found') -AllowFailure -LogFile $RunLog
    Remove-Item $AgentIDStateFile -Force -ErrorAction SilentlyContinue
    $script:NodeSPIFFEID = $null
    New-AgentJoinToken
    Kube -KubeArgs @('apply','-f',(Join-Path $RepositoryRoot 'deploy\spire\agent.yaml'))
}
function Assert-SpireAgentReady {
    param([int]$WaitSeconds = 90)
    if ([string]::IsNullOrWhiteSpace($script:NodeSPIFFEID)) {
        throw 'The expected SPIRE Agent ID has not been resolved from the join token.'
    }

    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    $lastOutput = 'SPIRE Server has not listed the token-derived Agent yet.'
    while ((Get-Date) -lt $deadline) {
        $agent = Invoke-NativeCapture -File 'kubectl' -Arguments @('--context',$Context,'exec','-n','spire','deploy/spire-server','--','/opt/spire/bin/spire-server','agent','show','-socketPath','/run/spire/sockets/server.sock','-spiffeID',$script:NodeSPIFFEID) -AllowFailure -LogFile $RunLog
        $lastOutput = $agent.Output
        $socket = Invoke-NativeCapture -File 'docker' -Arguments @('exec',$NodeContainer,'sh','-c','test -S /run/spire/sockets/agent.sock') -AllowFailure -LogFile $RunLog
        if ($agent.ExitCode -eq 0 -and $agent.Output -match [regex]::Escape($script:NodeSPIFFEID) -and $socket.ExitCode -eq 0) {
            Write-Ok "SPIRE Agent attested as $($script:NodeSPIFFEID) and published the Workload API socket."
            return
        }
        Start-Sleep -Seconds 2
    }

    throw "SPIRE Agent did not attest as $($script:NodeSPIFFEID) or publish its Workload API socket within $WaitSeconds seconds.`n$lastOutput"
}
function Ensure-SpireWorkloadEntry {
    param(
        [Parameter(Mandatory=$true)][string]$SPIFFEID,
        [Parameter(Mandatory=$true)][int]$UnixUID
    )

    $selector = "unix:uid:$UnixUID"
    $show = Invoke-NativeCapture -File 'kubectl' -Arguments @('--context',$Context,'exec','-n','spire','deploy/spire-server','--','/opt/spire/bin/spire-server','entry','show','-socketPath','/run/spire/sockets/server.sock','-spiffeID',$SPIFFEID) -AllowFailure -LogFile $RunLog
    $isCorrect = $show.ExitCode -eq 0 -and
        $show.Output -match [regex]::Escape($SPIFFEID) -and
        $show.Output -match [regex]::Escape($script:NodeSPIFFEID) -and
        $show.Output -match [regex]::Escape($selector)

    if (-not $isCorrect -and $show.Output) {
        $entryMatches = [regex]::Matches($show.Output, '(?im)^\s*Entry ID\s*:\s*(\S+)\s*$')
        foreach ($match in $entryMatches) {
            Invoke-Native -File 'kubectl' -Arguments @('--context',$Context,'exec','-n','spire','deploy/spire-server','--','/opt/spire/bin/spire-server','entry','delete','-socketPath','/run/spire/sockets/server.sock','-entryID',$match.Groups[1].Value) -AllowFailure -LogFile $RunLog
        }
    }

    if (-not $isCorrect) {
        Invoke-Native -File 'kubectl' -Arguments @('--context',$Context,'exec','-n','spire','deploy/spire-server','--','/opt/spire/bin/spire-server','entry','create','-socketPath','/run/spire/sockets/server.sock','-parentID',$script:NodeSPIFFEID,'-spiffeID',$SPIFFEID,'-selector',$selector,'-x509SVIDTTL','3600') -LogFile $RunLog
    }

    $verify = Invoke-NativeCapture -File 'kubectl' -Arguments @('--context',$Context,'exec','-n','spire','deploy/spire-server','--','/opt/spire/bin/spire-server','entry','show','-socketPath','/run/spire/sockets/server.sock','-spiffeID',$SPIFFEID) -AllowFailure -LogFile $RunLog
    if ($verify.ExitCode -ne 0 -or
        $verify.Output -notmatch [regex]::Escape($SPIFFEID) -or
        $verify.Output -notmatch [regex]::Escape($script:NodeSPIFFEID) -or
        $verify.Output -notmatch [regex]::Escape($selector)) {
        throw "SPIRE registration verification failed for $SPIFFEID. Expected parent $($script:NodeSPIFFEID) and selector $selector.`n$($verify.Output)"
    }
}

function Get-ResponseCollection {
    [CmdletBinding(PositionalBinding=$false)]
    param(
        [Parameter(Mandatory=$true)][AllowNull()][object]$Response,
        [Parameter(Mandatory=$true)][string]$PropertyName,
        [Parameter(Mandatory=$true)][string]$Endpoint
    )

    if ($null -eq $Response) {
        throw "Endpoint '$Endpoint' returned an empty response; expected JSON property '$PropertyName'."
    }

    # The documented API shape is an object such as { "events": [...] }.
    # Access the property through PSObject so Set-StrictMode does not turn an
    # absent optional collection into an opaque PropertyNotFoundException.
    $property = $Response.PSObject.Properties[$PropertyName]
    if ($null -ne $property) {
        if ($null -eq $property.Value) { return @() }
        return @($property.Value)
    }

    # Be tolerant of a top-level JSON array. Windows PowerShell and some
    # proxies can expose collection-only payloads this way even when the
    # upstream API normally wraps them in an object.
    if ($Response -is [System.Array]) {
        return @($Response)
    }

    # Invoke-RestMethod normally deserializes application/json. Be tolerant of
    # raw JSON and JSON that has been encoded as a JSON string by an intermediary.
    # Unwrap at most four layers so malformed or cyclic input cannot loop forever.
    if ($Response -is [string]) {
        $parsed = $Response
        for ($depth = 0; $depth -lt 4 -and $parsed -is [string]; $depth++) {
            try {
                $next = $parsed | ConvertFrom-Json -ErrorAction Stop
            } catch {
                break
            }
            if ($next -is [string] -and $next -eq $parsed) { break }
            $parsed = $next
        }

        if ($parsed -isnot [string]) {
            $parsedProperty = $parsed.PSObject.Properties[$PropertyName]
            if ($null -ne $parsedProperty) {
                if ($null -eq $parsedProperty.Value) { return @() }
                return @($parsedProperty.Value)
            }
            if ($parsed -is [System.Array]) { return @($parsed) }
        }
    }

    $available = @($Response.PSObject.Properties | ForEach-Object { $_.Name }) -join ', '
    if ([string]::IsNullOrWhiteSpace($available)) { $available = '<none>' }
    try {
        $preview = $Response | ConvertTo-Json -Depth 8 -Compress
    } catch {
        $preview = [string]$Response
    }
    if ($preview.Length -gt 1200) { $preview = $preview.Substring(0,1200) + '...' }
    throw "Endpoint '$Endpoint' did not return JSON property '$PropertyName'. Available properties: $available. Response: $preview"
}

function Get-NestedPropertyValue {
    [CmdletBinding(PositionalBinding=$false)]
    param(
        [AllowNull()][object]$Object,
        [Parameter(Mandatory=$true)][string]$PropertyName
    )
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$PropertyName]
    if ($null -eq $property) { return $null }
    return $property.Value
}


function Test-ResponseCollectionHandling {
    $wrapped = [pscustomobject]@{ events = @([pscustomobject]@{ id = 1 }, [pscustomobject]@{ id = 2 }) }
    $wrappedItems = @(Get-ResponseCollection -Response $wrapped -PropertyName 'events' -Endpoint 'self-test://wrapped')
    if ($wrappedItems.Count -ne 2 -or $wrappedItems[0].id -ne 1 -or $wrappedItems[1].id -ne 2) {
        throw 'The response collection helper failed its wrapped-object self-test.'
    }

    $singleWrapped = [pscustomobject]@{ events = @([pscustomobject]@{ id = 3 }) }
    $singleItems = @(Get-ResponseCollection -Response $singleWrapped -PropertyName 'events' -Endpoint 'self-test://single')
    if ($singleItems.Count -ne 1 -or $singleItems[0].id -ne 3) {
        throw 'The response collection helper failed its single-item self-test.'
    }

    $emptyWrapped = [pscustomobject]@{ events = @() }
    $emptyItems = @(Get-ResponseCollection -Response $emptyWrapped -PropertyName 'events' -Endpoint 'self-test://empty')
    if ($emptyItems.Count -ne 0) {
        throw 'The response collection helper failed its empty-collection self-test.'
    }

    $topLevel = @([pscustomobject]@{ id = 4 }, [pscustomobject]@{ id = 5 })
    $topLevelItems = @(Get-ResponseCollection -Response $topLevel -PropertyName 'events' -Endpoint 'self-test://top-level-array')
    if ($topLevelItems.Count -ne 2 -or $topLevelItems[0].id -ne 4 -or $topLevelItems[1].id -ne 5) {
        throw 'The response collection helper failed its top-level-array self-test.'
    }

    $rawJSON = '{"events":[{"id":6}]}'
    $rawItems = @(Get-ResponseCollection -Response $rawJSON -PropertyName 'events' -Endpoint 'self-test://raw-json')
    if ($rawItems.Count -ne 1 -or $rawItems[0].id -ne 6) {
        throw 'The response collection helper failed its raw-JSON self-test.'
    }

    $doubleEncodedJSON = $rawJSON | ConvertTo-Json -Compress
    $doubleEncodedItems = @(Get-ResponseCollection -Response $doubleEncodedJSON -PropertyName 'events' -Endpoint 'self-test://double-encoded-json')
    if ($doubleEncodedItems.Count -ne 1 -or $doubleEncodedItems[0].id -ne 6) {
        throw 'The response collection helper failed its double-encoded JSON self-test.'
    }
}

function Invoke-ContainGoSmokeTest([string]$BaseURL) {
    Write-Section 'Running full end-to-end platform verification'

    function Invoke-VerificationJob {
        param(
            [Parameter(Mandatory=$true)][string]$Client,
            [Parameter(Mandatory=$true)][string]$Method,
            [Parameter(Mandatory=$true)][string]$Path,
            [object]$Body = @{},
            [int]$Count = 1,
            [int]$Concurrency = 1,
            [int]$IntervalMS = 0,
            [switch]$Continuous,
            [int]$MaxDurationSeconds = 10
        )
        $payload = @{
            method = $Method
            path = $Path
            body = $Body
            count = $Count
            concurrency = $Concurrency
            interval_ms = $IntervalMS
            continuous = [bool]$Continuous
            max_duration_seconds = $MaxDurationSeconds
        } | ConvertTo-Json -Depth 8 -Compress

        $job = Invoke-RestMethod -Method Post -Uri "$BaseURL/api/ui/components/$Client/requests" -ContentType 'application/json' -Body $payload -TimeoutSec 20
        if (-not $job.id) { throw "$Client did not create a request job for $Method $Path." }

        $snapshot = $null
        for ($i=0; $i -lt 120; $i++) {
            Start-Sleep -Milliseconds 250
            $snapshot = Invoke-RestMethod -Method Get -Uri "$BaseURL/api/ui/components/$Client/jobs/$($job.id)" -TimeoutSec 20
            if ($snapshot.status -eq 'completed' -or $snapshot.status -eq 'cancelled') { break }
        }
        if (-not $snapshot -or $snapshot.status -ne 'completed') {
            $lastStatus = if ($snapshot) { [string]$snapshot.status } else { 'no response' }
            throw "$Client request job for $Method $Path did not complete. Last status: $lastStatus"
        }
        $jobEndpoint = "$BaseURL/api/ui/components/$Client/jobs/$($job.id)"
        $results = Get-ResponseCollection -Response $snapshot -PropertyName 'results' -Endpoint $jobEndpoint
        $result = @($results)[0]
        if (-not $result) { throw "$Client request job for $Method $Path completed without a result." }
        return $result
    }

    function Get-VerificationWorkload([string]$Name) {
        $endpoint = "$BaseURL/api/ui/workloads"
        $inventory = Invoke-RestMethod -Method Get -Uri $endpoint -TimeoutSec 20
        $workloads = Get-ResponseCollection -Response $inventory -PropertyName 'workloads' -Endpoint $endpoint
        return @($workloads | Where-Object { (Get-NestedPropertyValue -Object $_ -PropertyName 'name') -eq $Name })[0]
    }

    function Normalize-VerificationClient([string]$Name) {
        $state = Get-VerificationWorkload -Name $Name
        if (-not $state) { throw "Control Plane workload inventory is missing $Name." }
        if ($state.status -eq 'quarantined') {
            Invoke-RestMethod -Method Post -Uri "$BaseURL/api/ui/workloads/$Name/release" -ContentType 'application/json' -Body '{}' -TimeoutSec 20 | Out-Null
        } elseif ([int]$state.risk_score -gt 0) {
            Invoke-RestMethod -Method Post -Uri "$BaseURL/api/ui/workloads/$Name/reset-risk" -ContentType 'application/json' -Body '{}' -TimeoutSec 20 | Out-Null
        }
        $normalized = Get-VerificationWorkload -Name $Name
        if (-not $normalized -or $normalized.status -ne 'active' -or [int]$normalized.risk_score -ne 0) {
            throw "Unable to normalize $Name before verification."
        }
    }

    $topologyEndpoint = "$BaseURL/api/ui/topology"
    $topology = Invoke-RestMethod -Method Get -Uri $topologyEndpoint -TimeoutSec 15
    $topologyComponents = Get-ResponseCollection -Response $topology -PropertyName 'components' -Endpoint $topologyEndpoint
    $topologyEdges = Get-ResponseCollection -Response $topology -PropertyName 'edges' -Endpoint $topologyEndpoint
    if (@($topologyComponents).Count -ne 8 -or @($topologyEdges).Count -lt 8) {
        throw 'Dashboard topology API did not return the six workloads plus OPA and SPIRE with their expected connections.'
    }

    $expectedIDs = [ordered]@{
        'api-gateway'   = 'spiffe://containgo.local/ns/containgo/sa/api-gateway'
        'control-plane' = 'spiffe://containgo.local/ns/containgo/sa/control-plane'
        'dashboard'     = 'spiffe://containgo.local/ns/containgo/sa/dashboard'
        'order-client'  = 'spiffe://containgo.local/ns/containgo/sa/order-client'
        'report-client' = 'spiffe://containgo.local/ns/containgo/sa/report-client'
        'protected-api' = 'spiffe://containgo.local/ns/containgo/sa/protected-api'
    }
    foreach ($entry in $expectedIDs.GetEnumerator()) {
        $componentEndpoint = "$BaseURL/api/ui/components/$($entry.Key)"
        $component = Invoke-RestMethod -Method Get -Uri $componentEndpoint -TimeoutSec 20
        $identity = Get-NestedPropertyValue -Object $component -PropertyName 'identity'
        $identitySPIFFEID = Get-NestedPropertyValue -Object $identity -PropertyName 'spiffe_id'
        if (-not $identity -or $identitySPIFFEID -ne $entry.Value) {
            $identityError = Get-NestedPropertyValue -Object $component -PropertyName 'identity_error'
            $detail = if ($identityError) { $identityError } else { 'identity data was missing' }
            throw "Component '$($entry.Key)' did not return its expected SPIFFE identity. $detail"
        }
        $serialNumber = Get-NestedPropertyValue -Object $identity -PropertyName 'serial_number'
        $notAfter = Get-NestedPropertyValue -Object $identity -PropertyName 'not_after'
        if (-not $serialNumber -or -not $notAfter) {
            throw "Component '$($entry.Key)' returned an incomplete X.509-SVID description."
        }
    }

    Normalize-VerificationClient -Name 'order-client'
    Normalize-VerificationClient -Name 'report-client'

    $quarantineCreated = $false
    try {
        $allowed = Invoke-VerificationJob -Client 'order-client' -Method 'GET' -Path '/api/orders'
        if ([int]$allowed.status_code -ne 200 -or $allowed.decision -ne 'allow' -or -not $allowed.trace_id) {
            throw "Allowed order request failed. HTTP $($allowed.status_code), decision $($allowed.decision), error $($allowed.error)"
        }

        $created = Invoke-VerificationJob -Client 'order-client' -Method 'POST' -Path '/api/orders' -Body @{ customer = 'VERIFY-CUSTOMER'; amount = 25.50 }
        if ([int]$created.status_code -ne 201 -or $created.decision -ne 'allow') {
            throw "Authorized POST /api/orders failed. HTTP $($created.status_code), decision $($created.decision)."
        }

        $updated = Invoke-VerificationJob -Client 'order-client' -Method 'PUT' -Path '/api/orders/ORD-1001' -Body @{ status = 'verification-passed' }
        if ([int]$updated.status_code -ne 200 -or $updated.decision -ne 'allow') {
            throw "Authorized PUT /api/orders/ORD-1001 failed. HTTP $($updated.status_code), decision $($updated.decision)."
        }

        $generated = Invoke-VerificationJob -Client 'report-client' -Method 'POST' -Path '/api/reports/generate' -Body @{ name = 'ContainGo startup verification' }
        if ([int]$generated.status_code -ne 201 -or $generated.decision -ne 'allow') {
            throw "Authorized POST /api/reports/generate failed. HTTP $($generated.status_code), decision $($generated.decision)."
        }

        $sensitive1 = Invoke-VerificationJob -Client 'report-client' -Method 'GET' -Path '/api/payment-details'
        $sensitive2 = Invoke-VerificationJob -Client 'report-client' -Method 'GET' -Path '/api/payment-details'
        if ([int]$sensitive1.status_code -ne 403 -or $sensitive1.decision -ne 'deny' -or
            [int]$sensitive2.status_code -ne 403 -or $sensitive2.decision -ne 'deny') {
            throw 'Sensitive endpoint attempts were not denied as expected.'
        }

        $quarantined = Get-VerificationWorkload -Name 'report-client'
        if (-not $quarantined -or $quarantined.status -ne 'quarantined' -or [int]$quarantined.risk_score -lt 100) {
            throw "Two highly sensitive endpoint attempts did not quarantine report-client. Current status=$($quarantined.status), risk=$($quarantined.risk_score)."
        }
        $quarantineCreated = $true

        $blocked = Invoke-VerificationJob -Client 'report-client' -Method 'GET' -Path '/api/reports'
        if ([int]$blocked.status_code -ne 403 -or $blocked.decision -ne 'deny') {
            throw 'A normally authorized report request was not blocked after quarantine.'
        }

        Invoke-RestMethod -Method Post -Uri "$BaseURL/api/ui/workloads/report-client/release" -ContentType 'application/json' -Body '{}' -TimeoutSec 20 | Out-Null
        $quarantineCreated = $false
        $released = Get-VerificationWorkload -Name 'report-client'
        if (-not $released -or $released.status -ne 'active' -or [int]$released.risk_score -ne 0) {
            throw 'Administrative release did not restore report-client to active with risk score zero.'
        }

        $restored = Invoke-VerificationJob -Client 'report-client' -Method 'GET' -Path '/api/reports'
        if ([int]$restored.status_code -ne 200 -or $restored.decision -ne 'allow') {
            throw 'Normal report traffic did not recover after administrative release.'
        }

        # Query the exact trace instead of downloading hundreds of rich event
        # records. This avoids oversized responses as the persistent demo history
        # grows and verifies the Control Plane trace lookup API directly.
        $traceEndpoint = "$BaseURL/api/ui/traces/$([uri]::EscapeDataString([string]$allowed.trace_id))"
        $traceItems = @()
        for ($i=0; $i -lt 20; $i++) {
            try {
                $traceResponse = Invoke-RestMethod -Method Get -Uri $traceEndpoint -TimeoutSec 20
                $traceItems = @(Get-ResponseCollection -Response $traceResponse -PropertyName 'events' -Endpoint $traceEndpoint)
            } catch {
                $traceItems = @()
            }
            if ($traceItems.Count -gt 0) { break }
            Start-Sleep -Milliseconds 250
        }
        if ($traceItems.Count -lt 1) {
            throw "Allowed trace $($allowed.trace_id) was not persisted by the Control Plane."
        }
        $event = $traceItems[-1]
        $controlPlaneHop = Get-NestedPropertyValue -Object $event -PropertyName 'control_plane_hop'
        $decisionEvent = Get-NestedPropertyValue -Object $event -PropertyName 'decision_event'
        $hops = Get-NestedPropertyValue -Object $decisionEvent -PropertyName 'hops'
        if (-not $controlPlaneHop -or @($hops).Count -lt 3) {
            throw 'The persisted request is missing expected client/Gateway/OPA/Protected API/Control Plane trace evidence.'
        }

        $incidentsEndpoint = "$BaseURL/api/ui/incidents"
        $incidentsResponse = Invoke-RestMethod -Method Get -Uri $incidentsEndpoint -TimeoutSec 20
        $incidentItems = Get-ResponseCollection -Response $incidentsResponse -PropertyName 'incidents' -Endpoint $incidentsEndpoint
        $resolvedIncident = @($incidentItems | Where-Object {
            (Get-NestedPropertyValue -Object $_ -PropertyName 'workload') -eq 'report-client' -and
            (Get-NestedPropertyValue -Object $_ -PropertyName 'status') -eq 'resolved'
        })
        if ($resolvedIncident.Count -lt 1) {
            throw 'Quarantine was released, but the corresponding incident was not marked resolved.'
        }

        # Verify long-running request jobs can be cancelled without waiting for
        # their maximum duration.
        $continuousPayload = @{
            method = 'GET'; path = '/api/reports'; body = @{}; count = 1;
            concurrency = 1; interval_ms = 200; continuous = $true;
            max_duration_seconds = 10
        } | ConvertTo-Json -Depth 5 -Compress
        $continuousJob = Invoke-RestMethod -Method Post -Uri "$BaseURL/api/ui/components/report-client/requests" -ContentType 'application/json' -Body $continuousPayload -TimeoutSec 20
        Start-Sleep -Milliseconds 600
        Invoke-RestMethod -Method Delete -Uri "$BaseURL/api/ui/components/report-client/jobs/$($continuousJob.id)" -TimeoutSec 20 | Out-Null
        $cancelled = $null
        for ($i=0; $i -lt 80; $i++) {
            Start-Sleep -Milliseconds 150
            $cancelled = Invoke-RestMethod -Method Get -Uri "$BaseURL/api/ui/components/report-client/jobs/$($continuousJob.id)" -TimeoutSec 20
            if ($cancelled.status -eq 'cancelled') { break }
        }
        if (-not $cancelled -or $cancelled.status -ne 'cancelled') {
            throw 'Continuous request job cancellation was not confirmed.'
        }

        Write-Ok "Full verification passed: six SVIDs, GET/POST/PUT, OPA allow/deny, trace persistence, risk scoring, quarantine, release, recovery and job cancellation."
    }
    finally {
        try {
            $reportState = Get-VerificationWorkload -Name 'report-client'
            if ($reportState -and $reportState.status -eq 'quarantined') {
                Invoke-RestMethod -Method Post -Uri "$BaseURL/api/ui/workloads/report-client/release" -ContentType 'application/json' -Body '{}' -TimeoutSec 20 | Out-Null
            } elseif ($reportState -and [int]$reportState.risk_score -gt 0) {
                Invoke-RestMethod -Method Post -Uri "$BaseURL/api/ui/workloads/report-client/reset-risk" -ContentType 'application/json' -Body '{}' -TimeoutSec 20 | Out-Null
            }
            $orderState = Get-VerificationWorkload -Name 'order-client'
            if ($orderState -and $orderState.status -eq 'quarantined') {
                Invoke-RestMethod -Method Post -Uri "$BaseURL/api/ui/workloads/order-client/release" -ContentType 'application/json' -Body '{}' -TimeoutSec 20 | Out-Null
            } elseif ($orderState -and [int]$orderState.risk_score -gt 0) {
                Invoke-RestMethod -Method Post -Uri "$BaseURL/api/ui/workloads/order-client/reset-risk" -ContentType 'application/json' -Body '{}' -TimeoutSec 20 | Out-Null
            }
        } catch {
            Write-Warn "Verification cleanup could not completely restore client state: $($_.Exception.Message)"
        }
    }
}

function Get-FirstNamespacedResource {
    [CmdletBinding(PositionalBinding=$false)]
    param(
        [Parameter(Mandatory=$true)][string]$ResourceType,
        [Parameter(Mandatory=$true)][string]$Selector
    )

    $result = Invoke-NativeCapture -File 'kubectl' -Arguments @('--context',$Context,'get',$ResourceType,'-A','-l',$Selector,'--no-headers') -AllowFailure
    if ($result.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($result.Output)) { return $null }

    $lines = @($result.Output -split '\r?\n' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($lines.Count -eq 0) { return $null }
    $parts = @($lines[0].Trim() -split '\s+')
    if ($parts.Count -lt 2) { return $null }

    return [pscustomobject]@{
        Namespace = $parts[0]
        Name      = $parts[1]
    }
}
function Remove-LegacyClusterResources {
    $legacyNamespaces = @('spire-server','spire-system')
    $removedLegacySPIRE = $false

    foreach ($legacyNamespace in $legacyNamespaces) {
        $namespaceCheck = Invoke-NativeCapture -File 'kubectl' -Arguments @('--context',$Context,'get','namespace',$legacyNamespace) -AllowFailure
        if ($namespaceCheck.ExitCode -eq 0) {
            Write-Warn "Removing legacy SPIRE namespace '$legacyNamespace' before installing the unified SPIRE stack."
            Invoke-Native -File 'kubectl' -Arguments @('--context',$Context,'delete','namespace',$legacyNamespace,'--wait=true','--timeout=180s') -LogFile $RunLog
            $removedLegacySPIRE = $true
        }
    }

    Invoke-Native -File 'kubectl' -Arguments @('--context',$Context,'delete','deployment/democtl','service/democtl','serviceaccount/democtl','-n','containgo','--ignore-not-found') -AllowFailure -LogFile $RunLog
    Invoke-Native -File 'kubectl' -Arguments @('--context',$Context,'delete','networkpolicy','--all','-n','containgo','--ignore-not-found') -AllowFailure -LogFile $RunLog
    Invoke-Native -File 'kubectl' -Arguments @('--context',$Context,'delete','clusterspiffeid','--all','--ignore-not-found') -AllowFailure -LogFile $RunLog

    Invoke-Native -File 'kubectl' -Arguments @('--context',$Context,'delete','csidriver','csi.spiffe.io','--ignore-not-found') -AllowFailure -LogFile $RunLog
    if ($removedLegacySPIRE) {
        Invoke-Native -File 'docker' -Arguments @('exec',$NodeContainer,'sh','-c','rm -rf /run/spire/data/* /run/spire/sockets/*') -AllowFailure -LogFile $RunLog
        Write-Ok 'Legacy SPIRE/CSI resources were removed.'
    }
}
function Collect-Diagnostics([string]$Reason) {
    Write-Fail $Reason
    $diag = Join-Path $LogDirectory ("diagnostics-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    "ContainGo diagnostics: $Reason" | Out-File $diag

    # Diagnostic commands must never hide the original failure. In particular,
    # a damaged cluster may reject cluster-wide pod listing, which is itself
    # useful evidence rather than a second fatal PowerShell exception.
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        if (Get-Command docker -ErrorAction SilentlyContinue) {
            "`n=== docker info ===" | Out-File $diag -Append
            & docker info 2>&1 | Out-File $diag -Append
            "`n=== docker ps -a ===" | Out-File $diag -Append
            & docker ps -a 2>&1 | Out-File $diag -Append
            "`n=== kind control-plane logs ===" | Out-File $diag -Append
            & docker logs --tail 300 $NodeContainer 2>&1 | Out-File $diag -Append
        }
        if (Get-Command kubectl -ErrorAction SilentlyContinue) {
            "`n=== kubeconfig ===" | Out-File $diag -Append
            & kubectl config current-context 2>&1 | Out-File $diag -Append
            & kubectl config view --minify --raw 2>&1 | Out-File $diag -Append
            "`n=== Kubernetes API readiness ===" | Out-File $diag -Append
            & kubectl --context $Context get --raw=/readyz 2>&1 | Out-File $diag -Append
            "`n=== Kubernetes authorization ===" | Out-File $diag -Append
            $authorization = (& kubectl --context $Context auth can-i list pods --all-namespaces 2>&1 | Out-String).Trim()
            $authorization | Out-File $diag -Append

            if ($LASTEXITCODE -eq 0 -and $authorization -match '(?im)^\s*yes\s*$') {
                "`n=== pods ===" | Out-File $diag -Append
                & kubectl --context $Context get pods -A -o wide 2>&1 | Out-File $diag -Append
                "`n=== events ===" | Out-File $diag -Append
                & kubectl --context $Context get events -A --sort-by=.lastTimestamp 2>&1 | Out-File $diag -Append
                $badPods = & kubectl --context $Context get pods -A --no-headers 2>$null | Where-Object {
                    $columns = @($_.Trim() -split '\s+')
                    if ($columns.Count -lt 4) { return $true }
                    $readyParts = @($columns[2] -split '/')
                    $readyMismatch = $readyParts.Count -ne 2 -or $readyParts[0] -ne $readyParts[1]
                    $unexpectedStatus = $columns[3] -notin @('Running','Completed','Succeeded')
                    return $readyMismatch -or $unexpectedStatus
                }
                foreach ($line in $badPods) {
                    $columns = @($line.Trim() -split '\s+')
                    if ($columns.Count -ge 2) {
                        "`n=== describe $($columns[0])/$($columns[1]) ===" | Out-File $diag -Append
                        & kubectl --context $Context describe pod $columns[1] -n $columns[0] 2>&1 | Out-File $diag -Append
                        "`n=== logs $($columns[0])/$($columns[1]) ===" | Out-File $diag -Append
                        & kubectl --context $Context logs $columns[1] -n $columns[0] --all-containers --tail=200 2>&1 | Out-File $diag -Append
                        & kubectl --context $Context logs $columns[1] -n $columns[0] --all-containers --previous --tail=200 2>&1 | Out-File $diag -Append
                    }
                }

                "`n=== SPIRE server logs ===" | Out-File $diag -Append
                & kubectl --context $Context logs -n spire deployment/spire-server --tail=300 2>&1 | Out-File $diag -Append
                "`n=== SPIRE agent logs ===" | Out-File $diag -Append
                & kubectl --context $Context logs -n spire daemonset/spire-agent --tail=300 2>&1 | Out-File $diag -Append
                "`n=== SPIRE attested agents ===" | Out-File $diag -Append
                & kubectl --context $Context exec -n spire deploy/spire-server -- /opt/spire/bin/spire-server agent show -socketPath /run/spire/sockets/server.sock 2>&1 | Out-File $diag -Append
                "`n=== SPIRE registration entries ===" | Out-File $diag -Append
                & kubectl --context $Context exec -n spire deploy/spire-server -- /opt/spire/bin/spire-server entry show -socketPath /run/spire/sockets/server.sock 2>&1 | Out-File $diag -Append
                "`n=== SPIRE host paths ===" | Out-File $diag -Append
                & docker exec $NodeContainer sh -c 'ls -la /run/spire/data /run/spire/sockets' 2>&1 | Out-File $diag -Append
            } else {
                "Cluster-wide pod and event collection was skipped because the current kind administrator does not have the required access." | Out-File $diag -Append
            }
        }
    } catch {
        "Diagnostic collection itself encountered: $($_.Exception.Message)" | Out-File $diag -Append
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    Write-Host "Full diagnostics: $diag" -ForegroundColor Yellow
}

try {
    Write-Section 'Validating the PowerShell native-process runner'
    $nativeSelfTest = Invoke-NativeCapture -File $env:ComSpec -Arguments @('/d','/s','/c','echo ContainGo-Native-Runner') -AllowFailure -LogFile $RunLog
    if ($nativeSelfTest.ExitCode -ne 0 -or $nativeSelfTest.StdOut.Trim() -ne 'ContainGo-Native-Runner') {
        throw "The native-process runner failed its argument-quoting self-test.`n$($nativeSelfTest.Output)"
    }
    $stdinSelfTest = Invoke-NativeWithInput -File $env:ComSpec -Arguments @('/d','/s','/c','findstr /x ContainGo-STDIN') -InputText "ContainGo-STDIN`r`n" -AllowFailure -LogFile $RunLog
    if ($stdinSelfTest.ExitCode -ne 0 -or $stdinSelfTest.StdOut.Trim() -ne 'ContainGo-STDIN') {
        throw "The native-process runner failed its standard-input self-test.`n$($stdinSelfTest.Output)"
    }
    Test-ResponseCollectionHandling
    Write-Ok 'Native command argument quoting, stderr handling, standard input and JSON collection handling are functional.'

    Write-Section 'Cleaning obsolete demo files'
    & (Join-Path $PSScriptRoot 'remove-obsolete.ps1') -RepositoryRoot $RepositoryRoot
    Write-Ok 'Repository cleanup completed.'

    Write-Section 'Checking Docker and command-line tools'
    Test-DockerEngine
    Add-ToolPath $ToolDirectory
    $kindPath = Get-OrDownloadTool -Name 'kind' -FileName 'kind.exe' -Url 'https://github.com/kubernetes-sigs/kind/releases/download/v0.32.0/kind-windows-amd64' -ToolDirectory $ToolDirectory
    $kubectlPath = Get-OrDownloadTool -Name 'kubectl' -FileName 'kubectl.exe' -Url 'https://dl.k8s.io/release/v1.36.1/bin/windows/amd64/kubectl.exe' -ToolDirectory $ToolDirectory
    Write-Ok "kind: $kindPath"
    Write-Ok "kubectl: $kubectlPath"

    Write-Section 'Recovering or creating the kind cluster'
    $clusterList = Invoke-NativeCapture -File 'kind' -Arguments @('get','clusters') -AllowFailure -LogFile $RunLog
    $clusters = @($clusterList.Output -split '\r?\n' | Where-Object { $_ -and $_.Trim() })

    if ($Repair -and $clusters -contains $ClusterName) {
        Remove-ContainGoCluster "-Repair was supplied; recreating cluster '$ClusterName'. Existing in-cluster demo state will be removed."
        $clusters = @()
    }

    if ($clusters -notcontains $ClusterName) {
        New-ContainGoCluster
    } else {
        $inspect = Invoke-NativeCapture -File 'docker' -Arguments @('inspect','-f','{{.State.Running}}',$NodeContainer) -AllowFailure
        if ($inspect.ExitCode -ne 0) {
            Remove-ContainGoCluster 'kind metadata exists, but its node container is missing; removing stale state and recreating automatically.'
            New-ContainGoCluster
        } elseif ($inspect.Output.Trim().ToLowerInvariant() -ne 'true') {
            Write-Warn 'The kind control-plane container is stopped; restarting it.'
            Invoke-Native -File 'docker' -Arguments @('start',$NodeContainer) -LogFile $RunLog
        } else {
            Write-Ok 'Existing kind node is running.'
        }
    }

    $clusterHealth = $null
    try {
        $clusterHealth = Initialize-AndValidateCluster
    } catch {
        $clusterHealth = [pscustomobject]@{ Healthy = $false; Reason = $_.Exception.Message }
    }

    if (-not $clusterHealth.Healthy) {
        Remove-ContainGoCluster "Existing cluster recovery was unsafe: $($clusterHealth.Reason) Recreating it automatically."
        New-ContainGoCluster
        $clusterHealth = Initialize-AndValidateCluster
        if (-not $clusterHealth.Healthy) {
            throw "The recreated kind cluster is still unhealthy: $($clusterHealth.Reason)"
        }
    }
    Write-Ok "Kubernetes context $Context is ready and has valid cluster-administrator access."

    Write-Section 'Installing or repairing Calico networking'
    $kindnet = Invoke-NativeCapture -File 'kubectl' -Arguments @('--context',$Context,'get','daemonset','kindnet','-n','kube-system') -AllowFailure
    if ($kindnet.ExitCode -eq 0) {
        Write-Warn 'An older kindnet CNI was detected; removing it before enabling Calico NetworkPolicy enforcement.'
        Invoke-Native -File 'kubectl' -Arguments @('--context',$Context,'delete','daemonset','kindnet','-n','kube-system','--ignore-not-found') -LogFile $RunLog
    }

    $calicoNode = Get-FirstNamespacedResource -ResourceType 'daemonset' -Selector 'k8s-app=calico-node'
    if (-not $calicoNode) {
        $tigeraOperator = Invoke-NativeCapture -File 'kubectl' -Arguments @('--context',$Context,'get','deployment','tigera-operator','-n','tigera-operator') -AllowFailure
        if ($tigeraOperator.ExitCode -eq 0) {
            Write-Warn 'A Tigera Operator installation exists but calico-node is not visible yet; waiting for the operator-managed installation.'
            Invoke-Native -File 'kubectl' -Arguments @('--context',$Context,'rollout','status','deployment/tigera-operator','-n','tigera-operator','--timeout=240s') -LogFile $RunLog
            for ($i=0; $i -lt 60 -and -not $calicoNode; $i++) {
                Start-Sleep -Seconds 2
                $calicoNode = Get-FirstNamespacedResource -ResourceType 'daemonset' -Selector 'k8s-app=calico-node'
            }
            if (-not $calicoNode) { throw 'The Tigera Operator is installed, but it did not create a calico-node DaemonSet. Inspect the Installation resource and tigera-operator logs.' }
        } else {
            Write-Host 'Calico is not installed; applying the pinned Calico 3.32.0 manifest.'
            Invoke-Native -File 'kubectl' -Arguments @('--context',$Context,'apply','-f','https://raw.githubusercontent.com/projectcalico/calico/v3.32.0/manifests/calico.yaml') -LogFile $RunLog
            for ($i=0; $i -lt 60 -and -not $calicoNode; $i++) {
                Start-Sleep -Seconds 2
                $calicoNode = Get-FirstNamespacedResource -ResourceType 'daemonset' -Selector 'k8s-app=calico-node'
            }
            if (-not $calicoNode) { throw 'Calico installation completed without creating a calico-node DaemonSet.' }
        }
    } else {
        Write-Ok "Existing Calico installation detected in namespace '$($calicoNode.Namespace)'."
    }

    Invoke-Native -File 'kubectl' -Arguments @('--context',$Context,'rollout','status',"daemonset/$($calicoNode.Name)",'-n',$calicoNode.Namespace,'--timeout=240s') -LogFile $RunLog
    $calicoControllers = Get-FirstNamespacedResource -ResourceType 'deployment' -Selector 'k8s-app=calico-kube-controllers'
    if ($calicoControllers) {
        Invoke-Native -File 'kubectl' -Arguments @('--context',$Context,'rollout','status',"deployment/$($calicoControllers.Name)",'-n',$calicoControllers.Namespace,'--timeout=240s') -LogFile $RunLog
    }
    Invoke-Native -File 'kubectl' -Arguments @('--context',$Context,'rollout','status','deployment/coredns','-n','kube-system','--timeout=240s') -LogFile $RunLog
    Invoke-Native -File 'kubectl' -Arguments @('--context',$Context,'wait','--for=condition=Ready',"node/$NodeContainer",'--timeout=240s') -LogFile $RunLog
    Write-Ok 'Calico, cluster DNS and the Kubernetes node are ready.'

    Write-Section 'Building and loading ContainGo images'
    $sourceHash = Get-SourceHash $RepositoryRoot
    $hashFile = Join-Path $StateDirectory 'image-source.hash'
    $oldHash = if (Test-Path $hashFile) { (Get-Content $hashFile -Raw).Trim() } else { '' }
    $appImage = Invoke-NativeCapture -File 'docker' -Arguments @('image','inspect','containgo:local') -AllowFailure
    $appImageExists = $appImage.ExitCode -eq 0
    $helperImage = Invoke-NativeCapture -File 'docker' -Arguments @('image','inspect','containgo-spiffe-helper:local') -AllowFailure
    $helperImageExists = $helperImage.ExitCode -eq 0
    if ($RebuildImages -or -not $appImageExists -or $sourceHash -ne $oldHash) {
        Invoke-Native -File 'docker' -Arguments @('build','--pull','-t','containgo:local','-f',(Join-Path $RepositoryRoot 'build\docker\Dockerfile'),$RepositoryRoot) -LogFile $RunLog
    } else { Write-Ok 'Application source is unchanged; reusing containgo:local.' }
    if ($RebuildImages -or -not $helperImageExists) {
        Invoke-Native -File 'docker' -Arguments @('build','--pull','-t','containgo-spiffe-helper:local','-f',(Join-Path $RepositoryRoot 'build\docker\spiffe-helper.Dockerfile'),$RepositoryRoot) -LogFile $RunLog
    } else { Write-Ok 'Reusing containgo-spiffe-helper:local.' }
    Set-Content -Path $hashFile -Value $sourceHash
    Invoke-Native -File 'kind' -Arguments @('load','docker-image','containgo:local','containgo-spiffe-helper:local','--name',$ClusterName) -LogFile $RunLog
    Write-Ok 'Images are loaded into kind.'

    Write-Section 'Removing obsolete in-cluster demo resources'
    Remove-LegacyClusterResources
    Write-Ok 'Cluster migration cleanup completed.'

    Write-Section 'Starting SPIRE and registering workload identities'
    $namespaceManifest = Invoke-NativeCapture -File 'kubectl' -Arguments @('--context',$Context,'create','namespace','spire','--dry-run=client','-o','yaml') -LogFile $RunLog
    $namespaceApply = Invoke-NativeWithInput -File 'kubectl' -Arguments @('--context',$Context,'apply','-f','-') -InputText $namespaceManifest.StdOut -LogFile $RunLog
    if ($namespaceApply.Output) { Write-Host $namespaceApply.Output }

    $caCertArg = '--from-file=root-ca.crt=' + (Join-Path $RepositoryRoot 'deploy\spire\root-ca.crt')
    $caKeyArg = '--from-file=root-ca.key=' + (Join-Path $RepositoryRoot 'deploy\spire\root-ca.key')
    $secretManifest = Invoke-NativeCapture -File 'kubectl' -Arguments @('--context',$Context,'create','secret','generic','spire-root-ca','-n','spire',$caCertArg,$caKeyArg,'--dry-run=client','-o','yaml') -LogFile $RunLog
    $secretApply = Invoke-NativeWithInput -File 'kubectl' -Arguments @('--context',$Context,'apply','-f','-') -InputText $secretManifest.StdOut -LogFile $RunLog
    if ($secretApply.Output) { Write-Host $secretApply.Output }

    Kube -KubeArgs @('apply','-f',(Join-Path $RepositoryRoot 'deploy\spire\server.yaml'))
    Invoke-Native -File 'kubectl' -Arguments @('--context',$Context,'rollout','status','deployment/spire-server','-n','spire','--timeout=180s') -LogFile $RunLog
    Invoke-Native -File 'kubectl' -Arguments @('--context',$Context,'exec','-n','spire','deploy/spire-server','--','/opt/spire/bin/spire-server','healthcheck','-socketPath','/run/spire/sockets/server.sock') -LogFile $RunLog

    # Remove the workload alias produced by V4's incorrect token -spiffeID
    # usage. It is not an Agent record and must not be used as a parent.
    Remove-SpireEntriesBySPIFFEID -SPIFFEID $LegacyAgentAlias

    $agentCheck = Invoke-NativeCapture -File 'kubectl' -Arguments @('--context',$Context,'get','daemonset','spire-agent','-n','spire') -AllowFailure
    $agentExists = $agentCheck.ExitCode -eq 0
    $resolvedAgentID = Resolve-CurrentAgentID

    if (-not $resolvedAgentID) {
        Repair-SpireAgent
        $agentExists = $true
    } else {
        Write-Ok "Resolved the real token-derived SPIRE Agent ID: $resolvedAgentID"
        Kube -KubeArgs @('apply','-f',(Join-Path $RepositoryRoot 'deploy\spire\agent.yaml'))
    }

    $agentRollout = Invoke-NativeCapture -File 'kubectl' -Arguments @('--context',$Context,'rollout','status','daemonset/spire-agent','-n','spire','--timeout=180s') -AllowFailure -LogFile $RunLog
    if ($agentRollout.Output) { Write-Host $agentRollout.Output }
    $agentHealthy = $agentRollout.ExitCode -eq 0
    if ($agentHealthy) {
        try {
            Assert-SpireAgentReady -WaitSeconds 60
        } catch {
            Write-Warn $_.Exception.Message
            $agentHealthy = $false
        }
    }
    if (-not $agentHealthy) {
        Repair-SpireAgent
        Invoke-Native -File 'kubectl' -Arguments @('--context',$Context,'rollout','status','daemonset/spire-agent','-n','spire','--timeout=180s') -LogFile $RunLog
        Assert-SpireAgentReady -WaitSeconds 90
    }

    $identityMap = [ordered]@{
        'api-gateway' = 10001; 'control-plane' = 10002; 'dashboard' = 10003;
        'order-client' = 10004; 'report-client' = 10005; 'protected-api' = 10006
    }
    foreach ($entry in $identityMap.GetEnumerator()) {
        $spiffeID = "spiffe://containgo.local/ns/containgo/sa/$($entry.Key)"
        Ensure-SpireWorkloadEntry -SPIFFEID $spiffeID -UnixUID ([int]$entry.Value)
    }
    Write-Ok 'SPIRE Server, Agent and all six workload registration entries are verified.'

    Write-Section 'Deploying the application workloads'
    $deployments = @('control-plane','protected-api','api-gateway','order-client','report-client','dashboard')
    Remove-IncompatibleApplicationDeployments -Names $deployments
    Kube -KubeArgs @('apply','-f',(Join-Path $RepositoryRoot 'deploy\kubernetes\base.yaml'))
    Kube -KubeArgs @('apply','-f',(Join-Path $RepositoryRoot 'deploy\kubernetes\network-policies.yaml'))
    foreach ($deployment in $deployments) {
        Invoke-Native -File 'kubectl' -Arguments @('--context',$Context,'rollout','restart',"deployment/$deployment",'-n','containgo') -LogFile $RunLog
    }
    foreach ($deployment in $deployments) {
        Invoke-Native -File 'kubectl' -Arguments @('--context',$Context,'rollout','status',"deployment/$deployment",'-n','containgo','--timeout=240s') -LogFile $RunLog
    }
    Write-Ok 'All six ContainGo workloads are ready.'

    Write-Section 'Starting the Dashboard'
    $url = "http://127.0.0.1:$DashboardPort"
    $readyUrl = "$url/readyz"
    if (-not (Test-HttpReady $readyUrl)) {
        Stop-SavedProcess $PortPidFile
        if (Test-LocalPort $DashboardPort) { throw "Local port $DashboardPort is occupied by another process. Stop it or run with -DashboardPort <another-port>." }
        $PortErrorLog = Join-Path $LogDirectory 'dashboard-port-forward-error.log'
        Remove-Item $PortLog,$PortErrorLog -Force -ErrorAction SilentlyContinue
        $process = Start-Process -FilePath 'kubectl' -ArgumentList @('--context',$Context,'-n','containgo','port-forward','service/dashboard',"${DashboardPort}:8060") -WindowStyle Hidden -PassThru -RedirectStandardOutput $PortLog -RedirectStandardError $PortErrorLog
        Set-Content -Path $PortPidFile -Value $process.Id
        $dashboardReady = $false
        for ($i=0; $i -lt 45; $i++) {
            Start-Sleep -Seconds 1
            if (Test-HttpReady $readyUrl) { $dashboardReady = $true; break }
            if ($process.HasExited) { break }
        }
        if (-not $dashboardReady) {
            $stdout = if (Test-Path $PortLog) { Get-Content $PortLog -Raw } else { '' }
            $stderr = if (Test-Path $PortErrorLog) { Get-Content $PortErrorLog -Raw } else { '' }
            $forwardOutput = ($stdout + "`n" + $stderr).Trim()
            if (-not $forwardOutput) { $forwardOutput = 'No port-forward output was produced.' }
            throw "Dashboard port-forward or readiness failed:`n$forwardOutput"
        }
    } else { Write-Ok 'An existing healthy Dashboard port-forward was reused.' }
    if (-not $SkipSmokeTest) { Invoke-ContainGoSmokeTest -BaseURL $url }
    Write-Ok "ContainGo is ready at $url"
    Write-Host "Architecture:  $url/architecture"
    Write-Host "Control panel: $url/control-panel"
    Write-Host "Startup log:   $RunLog"
    if (-not $NoBrowser) { Start-Process $url | Out-Null }
}
catch {
    Collect-Diagnostics $_.Exception.Message
    exit 1
}
