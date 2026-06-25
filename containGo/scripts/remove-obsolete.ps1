[CmdletBinding()]
param([string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot))

# These paths belonged to the earlier scripted/demo implementation. The new
# implementation uses internal/platform, internal/clientservice,
# internal/controlservice and internal/uiconsole instead.
$legacyPaths = @(
    'internal/apigateway',
    'internal/config',
    'internal/controlplane',
    'internal/dashboard',
    'internal/database',
    'internal/domain',
    'internal/protectedapi',
    'internal/repository',
    'internal/risk',
    'internal/testutil',
    'internal/workloadclient',
    'migrations',
    'scripts/start-demo-showcase.ps1'
)

foreach ($relative in $legacyPaths) {
    $path = Join-Path $RepositoryRoot $relative
    if (Test-Path $path) {
        Remove-Item -Force -Recurse $path
        Write-Host "Removed obsolete path: $relative"
    }
}

# Old phase launchers are deliberately removed when this package is extracted
# over an existing checkout, so there is only one supported startup path.
Get-ChildItem -Path (Join-Path $RepositoryRoot 'scripts') -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^phase(10|11)-.*\.ps1$' } |
    ForEach-Object {
        Remove-Item -Force $_.FullName
        Write-Host "Removed obsolete script: scripts/$($_.Name)"
    }
