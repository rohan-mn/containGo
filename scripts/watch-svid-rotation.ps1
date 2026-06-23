param(
    [string]$Component = "api-gateway",
    [string]$ClusterName = "containgo",
    [int]$TimeoutSeconds = 1800,
    [int]$PollSeconds = 15
)

$ErrorActionPreference = "Stop"
$context = "kind-$ClusterName"
$namespace = "containgo"

function Read-Serials {
    $lines = @(
        kubectl `
            --context $context `
            --namespace $namespace `
            logs "deployment/$Component" `
            --container $Component `
            --since=40m
    )

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read $Component logs."
    }

    $serials = @()
    foreach ($line in $lines) {
        if ($line -match 'serial=([0-9]+)') {
            $serials += $Matches[1]
        }
    }

    return @($serials | Select-Object -Unique)
}

$initial = @(Read-Serials)
$initialSerial = if ($initial.Count -gt 0) { $initial[-1] } else { "" }

Write-Host "Watching $Component for an X.509-SVID rotation..."
if ($initialSerial -ne "") {
    Write-Host "Current serial: $initialSerial"
}

$deadline = (Get-Date).AddSeconds($TimeoutSeconds)

do {
    Start-Sleep -Seconds $PollSeconds
    $serials = @(Read-Serials)

    foreach ($serial in $serials) {
        if ($initialSerial -eq "") {
            $initialSerial = $serial
            Write-Host "Current serial: $initialSerial"
            continue
        }

        if ($serial -ne $initialSerial) {
            Write-Host "SVID rotation verified."
            Write-Host "Previous serial: $initialSerial"
            Write-Host "New serial:      $serial"
            exit 0
        }
    }
}
while ((Get-Date) -lt $deadline)

throw "No SVID rotation was observed within $TimeoutSeconds seconds."
