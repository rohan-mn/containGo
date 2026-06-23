param(
    [string]$OPAImage = "openpolicyagent/opa:1.17.1-static"
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Required command 'docker' was not found on PATH."
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$policyDirectory = Join-Path $projectRoot "policies"

Write-Host "> docker run --rm --volume ${policyDirectory}:/policies:ro $OPAImage test /policies --verbose"

docker run `
    --rm `
    --volume "${policyDirectory}:/policies:ro" `
    $OPAImage `
    test `
    /policies `
    --verbose

if ($LASTEXITCODE -ne 0) {
    throw "OPA policy tests failed."
}

Write-Host "OPA policy tests passed."
