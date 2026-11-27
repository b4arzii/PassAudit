# Shared helpers for PassAudit development scripts. Dot-source from other scripts:
#   . "$PSScriptRoot/_common.ps1"
# Compatible with Windows PowerShell 5.1 and PowerShell 7+. Keep this file ASCII-only.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$script:FrontendDir = Join-Path $script:RepoRoot 'frontend'
$script:VenvDir = Join-Path $script:RepoRoot '.venv'
# Windows PowerShell 5.1 has no $IsWindows, so ask for the path separator instead.
$script:OnWindows = [System.IO.Path]::DirectorySeparatorChar -eq '\'
$script:VenvPython = if ($script:OnWindows) {
    Join-Path (Join-Path $script:VenvDir 'Scripts') 'python.exe'
} else {
    Join-Path (Join-Path $script:VenvDir 'bin') 'python'
}
# npm is a .cmd shim on Windows and a plain executable elsewhere.
$script:NpmCommand = if ($script:OnWindows) { 'npm.cmd' } else { 'npm' }

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host ''
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Assert-Venv {
    if (-not (Test-Path $script:VenvPython)) {
        throw "Virtual environment not found at $script:VenvDir. Run scripts\setup.ps1 first."
    }
}

function Assert-FrontendDeps {
    if (-not (Test-Path (Join-Path $script:FrontendDir 'node_modules'))) {
        throw 'Frontend dependencies not installed. Run scripts\setup.ps1 first.'
    }
}

# Run a native command and fail loudly on a non-zero exit code.
function Invoke-Native {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments = @()
    )
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $($Arguments -join ' ')"
    }
}

# Return $true if a native command exits 0. Output is discarded; stderr never throws (PS 5.1).
function Test-NativeSuccess {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments = @()
    )
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $FilePath @Arguments 2>&1 | Out-Null
        return ($LASTEXITCODE -eq 0)
    }
    catch { return $false }
    finally { $ErrorActionPreference = $previous }
}

# Run a venv-python module, e.g. Invoke-VenvModule ruff check .
function Invoke-VenvModule {
    param(
        [Parameter(Mandatory)][string]$Module,
        [string[]]$Arguments = @()
    )
    Assert-Venv
    Invoke-Native -FilePath $script:VenvPython -Arguments (@('-m', $Module) + $Arguments)
}

# Run an npm script inside frontend/.
function Invoke-Npm {
    param([Parameter(Mandatory)][string[]]$Arguments)
    Assert-FrontendDeps
    Push-Location $script:FrontendDir
    try {
        Invoke-Native -FilePath $script:NpmCommand -Arguments $Arguments
    }
    finally {
        Pop-Location
    }
}
