Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Section([string]$Message) {
    Write-Host "`n=== $Message ===" -ForegroundColor Cyan
}
function Write-Ok([string]$Message) {
    Write-Host "[OK] $Message" -ForegroundColor Green
}
function Write-Warn([string]$Message) {
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}
function Write-Fail([string]$Message) {
    Write-Host "[FAILED] $Message" -ForegroundColor Red
}
function Require-Windows {
    if ($PSVersionTable.PSVersion.Major -lt 5) { throw "PowerShell 5.1 or newer is required." }
    if ($env:OS -ne "Windows_NT") { throw "This one-click launcher currently targets Windows with Docker Desktop." }
}
function Add-ToolPath([string]$ToolDirectory) {
    if (-not (Test-Path $ToolDirectory)) { New-Item -ItemType Directory -Force -Path $ToolDirectory | Out-Null }
    if (($env:PATH -split ';') -notcontains $ToolDirectory) { $env:PATH = "$ToolDirectory;$env:PATH" }
}
function Get-OrDownloadTool {
    param([string]$Name, [string]$FileName, [string]$Url, [string]$ToolDirectory)
    $existing = Get-Command $Name -ErrorAction SilentlyContinue
    if ($existing) { return $existing.Source }
    $target = Join-Path $ToolDirectory $FileName
    if (-not (Test-Path $target)) {
        Write-Warn "$Name is not installed; downloading the pinned local copy."
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $target
        } catch {
            throw "Unable to download $Name from $Url. Check internet/proxy access. $($_.Exception.Message)"
        }
    }
    return $target
}

function ConvertTo-NativeArgument {
    param([AllowEmptyString()][string]$Value)
    if ($null -eq $Value -or $Value.Length -eq 0) { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }

    # Windows native-process argument escaping. Backslashes immediately before a
    # quote (and trailing backslashes before the closing quote) must be doubled.
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $slashes++
            continue
        }
        if ($character -eq '"') {
            if ($slashes -gt 0) { [void]$builder.Append((('\' * ($slashes * 2)) -join '')) }
            [void]$builder.Append('\"')
            $slashes = 0
            continue
        }
        if ($slashes -gt 0) {
            [void]$builder.Append((('\' * $slashes) -join ''))
            $slashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($slashes -gt 0) { [void]$builder.Append((('\' * ($slashes * 2)) -join '')) }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Invoke-NativeProcess {
    [CmdletBinding(PositionalBinding=$false)]
    param(
        [Parameter(Mandatory=$true)][string]$File,
        [string[]]$Arguments = @(),
        [AllowNull()][string]$InputText = $null,
        [string]$LogFile
    )

    $argumentString = (($Arguments | ForEach-Object { ConvertTo-NativeArgument -Value ([string]$_) }) -join ' ')
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $File
    $startInfo.Arguments = $argumentString
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.RedirectStandardInput = $null -ne $InputText

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) { throw "Unable to start native command '$File'." }
    } catch {
        throw "Unable to start native command '$File'. Verify that it is installed and on PATH. $($_.Exception.Message)"
    }

    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if ($null -ne $InputText) {
        $process.StandardInput.Write($InputText)
        $process.StandardInput.Close()
    }
    $process.WaitForExit()
    $stdout = $stdoutTask.Result
    $stderr = $stderrTask.Result
    $code = $process.ExitCode
    $process.Dispose()

    $parts = @()
    if (-not [string]::IsNullOrWhiteSpace($stdout)) { $parts += $stdout.TrimEnd() }
    if (-not [string]::IsNullOrWhiteSpace($stderr)) { $parts += $stderr.TrimEnd() }
    $combined = ($parts -join [Environment]::NewLine)

    if ($LogFile -and -not [string]::IsNullOrWhiteSpace($combined)) {
        Add-Content -Path $LogFile -Value $combined
    }

    return [pscustomobject]@{
        ExitCode = $code
        StdOut   = $stdout.Trim()
        StdErr   = $stderr.Trim()
        Output   = $combined.Trim()
        Command  = "$File $argumentString".Trim()
    }
}

function Invoke-Native {
    [CmdletBinding(PositionalBinding=$false)]
    param(
        [Parameter(Mandatory=$true)][string]$File,
        [Parameter(Mandatory=$true)][string[]]$Arguments,
        [switch]$AllowFailure,
        [string]$LogFile
    )
    $result = Invoke-NativeProcess -File $File -Arguments $Arguments -LogFile $LogFile
    if ($result.Output) { Write-Host $result.Output }
    if ($result.ExitCode -ne 0 -and -not $AllowFailure) {
        throw "$File failed with exit code $($result.ExitCode). Arguments: $($Arguments -join ' ')`n$($result.Output)"
    }
}

function Invoke-NativeCapture {
    [CmdletBinding(PositionalBinding=$false)]
    param(
        [Parameter(Mandatory=$true)][string]$File,
        [string[]]$Arguments = @(),
        [switch]$AllowFailure,
        [string]$LogFile
    )
    $result = Invoke-NativeProcess -File $File -Arguments $Arguments -LogFile $LogFile
    if ($result.ExitCode -ne 0 -and -not $AllowFailure) {
        throw "$File failed with exit code $($result.ExitCode). Arguments: $($Arguments -join ' ')`n$($result.Output)"
    }
    return $result
}

function Invoke-NativeWithInput {
    [CmdletBinding(PositionalBinding=$false)]
    param(
        [Parameter(Mandatory=$true)][string]$File,
        [string[]]$Arguments = @(),
        [Parameter(Mandatory=$true)][string]$InputText,
        [switch]$AllowFailure,
        [string]$LogFile
    )
    $result = Invoke-NativeProcess -File $File -Arguments $Arguments -InputText $InputText -LogFile $LogFile
    if ($result.ExitCode -ne 0 -and -not $AllowFailure) {
        throw "$File failed with exit code $($result.ExitCode). Arguments: $($Arguments -join ' ')`n$($result.Output)"
    }
    return $result
}

function Test-DockerEngine {
    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $docker) { throw "Docker CLI is not installed. Install Docker Desktop for Windows, then run this script again." }

    $info = Invoke-NativeCapture -File 'docker' -Arguments @('info','--format','{{json .}}') -AllowFailure
    if ($info.ExitCode -eq 0) {
        $os = Invoke-NativeCapture -File 'docker' -Arguments @('info','--format','{{.OSType}}') -AllowFailure
        if ($os.StdOut.Trim() -ne 'linux') { throw "Docker is running Windows containers. Switch Docker Desktop to Linux containers." }
        Write-Ok "Docker Engine is running in Linux-container mode."
        return
    }

    $desktopProcess = Get-Process -Name 'Docker Desktop','com.docker.backend' -ErrorAction SilentlyContinue
    $desktopPath = Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'
    if (-not $desktopProcess -and (Test-Path $desktopPath)) {
        Write-Warn "Docker Desktop is installed but not running. Starting it now."
        Start-Process -FilePath $desktopPath | Out-Null
        for ($i=0; $i -lt 60; $i++) {
            Start-Sleep -Seconds 2
            $retry = Invoke-NativeCapture -File 'docker' -Arguments @('info','--format','{{.OSType}}') -AllowFailure
            if ($retry.ExitCode -eq 0) {
                if ($retry.StdOut.Trim() -ne 'linux') { throw "Docker Desktop started in Windows-container mode. Switch it to Linux containers." }
                Write-Ok "Docker Desktop started and the Linux engine is ready."
                return
            }
        }
        throw "Docker Desktop started, but its engine never became reachable. Open Docker Desktop and inspect its diagnostics."
    }
    if ($info.Output -match 'permission denied|access is denied') { throw "Docker Engine access was denied. Start Docker Desktop and verify that your Windows user can use Docker." }
    if ($info.Output -match 'WSL|wsl') { throw "Docker Engine is unreachable and the output mentions WSL. Verify WSL 2 with 'wsl --status' and restart Docker Desktop." }
    throw "Docker Engine is unreachable. Docker CLI exists, but 'docker info' failed:`n$($info.Output)"
}
function Test-HttpReady([string]$Url) {
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 3
        return $response.StatusCode -eq 200
    } catch { return $false }
}
function Test-LocalPort([int]$Port) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(300)) { return $false }
        $client.EndConnect($async)
        return $true
    } catch { return $false } finally { $client.Close() }
}
function Stop-SavedProcess([string]$PidFile) {
    if (-not (Test-Path $PidFile)) { return }
    $value = (Get-Content $PidFile -Raw).Trim()
    if ($value -match '^\d+$') {
        $process = Get-Process -Id ([int]$value) -ErrorAction SilentlyContinue
        if ($process) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
    }
    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
}
function Get-SourceHash([string]$Root) {
    $files = Get-ChildItem -Path (Join-Path $Root 'cmd'),(Join-Path $Root 'internal'),(Join-Path $Root 'go.mod'),(Join-Path $Root 'build') -File -Recurse | Sort-Object FullName
    $joined = ($files | ForEach-Object { (Get-FileHash $_.FullName -Algorithm SHA256).Hash }) -join ''
    $bytes = [Text.Encoding]::UTF8.GetBytes($joined)
    $sha = [Security.Cryptography.SHA256]::Create()
    return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()
}
