<#
.SYNOPSIS
    One-shot developer setup: Python venv, backend + frontend dependencies, .env.
.DESCRIPTION
    Idempotent - safe to re-run. Requires Python 3.12+ and Node.js 22+.
.PARAMETER Recreate
    Delete and recreate the virtual environment.
#>
[CmdletBinding()]
param(
    [switch]$Recreate
)

. "$PSScriptRoot/_common.ps1"
Set-Location $script:RepoRoot

Write-Step 'Checking prerequisites'
# Prefer the Windows py launcher pinned to 3.12; fall back to python / python3 on PATH.
$pyExe = $null
$pyPrefix = @()
if ($script:OnWindows -and (Get-Command py -ErrorAction SilentlyContinue) -and
    (Test-NativeSuccess -FilePath 'py' -Arguments @('-3.12', '--version'))) {
    $pyExe = 'py'
    $pyPrefix = @('-3.12')
}
elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $pyExe = 'python'
}
elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    $pyExe = 'python3'
}
else {
    throw 'Python 3.12+ not found. Install it from https://www.python.org/downloads/'
}
$pyVersion = & $pyExe @pyPrefix -c "import sys; print(str(sys.version_info.major) + '.' + str(sys.version_info.minor))"
if ([version]$pyVersion -lt [version]'3.12') { throw "Python 3.12+ required, found $pyVersion" }
Write-Host "Python $pyVersion"

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw 'Node.js 22+ not found. Install it from https://nodejs.org/'
}
$nodeMajor = [int]((node --version).TrimStart('v').Split('.')[0])
if ($nodeMajor -lt 22) { throw "Node.js 22+ required, found $(node --version)" }
Write-Host "Node $(node --version)"

Write-Step 'Creating Python virtual environment'
if ($Recreate -and (Test-Path $script:VenvDir)) {
    Remove-Item -Recurse -Force $script:VenvDir
}
if (-not (Test-Path $script:VenvPython)) {
    Invoke-Native -FilePath $pyExe -Arguments ($pyPrefix + @('-m', 'venv', $script:VenvDir))
} else {
    Write-Host '.venv already exists (use -Recreate to rebuild)'
}

Write-Step 'Installing backend dependencies'
Invoke-VenvModule -Module pip -Arguments @('install', '--upgrade', 'pip')
Invoke-VenvModule -Module pip -Arguments @('install', '-e', '.[dev]')

# Windows Smart App Control / WDAC can block mypy's compiled native extensions.
# If mypy cannot start, fall back to the pure-Python build (slower, but identical results).
if (-not (Test-NativeSuccess -FilePath $script:VenvPython -Arguments @('-m', 'mypy', '--version'))) {
    Write-Warning 'mypy native extensions are blocked by Application Control; installing pure-Python mypy.'
    Invoke-VenvModule -Module pip -Arguments @('uninstall', '-y', 'mypy', 'librt', 'ast-serialize')
    Invoke-VenvModule -Module pip -Arguments @('install', '--no-binary', 'mypy', 'mypy>=1.14,<1.19')
}

# Same story for pip-audit, whose tomli / charset-normalizer wheels ship compiled code.
if (-not (Test-NativeSuccess -FilePath $script:VenvPython -Arguments @('-m', 'pip_audit', '--version'))) {
    Write-Warning 'pip-audit dependencies are blocked by Application Control; installing pure-Python builds.'
    Invoke-VenvModule -Module pip -Arguments @(
        'install', '--force-reinstall', '--no-deps',
        '--no-binary', 'tomli', '--no-binary', 'charset-normalizer', 'tomli', 'charset-normalizer'
    )
}

Write-Step 'Installing frontend dependencies'
Push-Location $script:FrontendDir
try {
    $installCmd = if (Test-Path 'package-lock.json') { 'ci' } else { 'install' }
    Invoke-Native -FilePath $script:NpmCommand -Arguments @($installCmd)
}
finally {
    Pop-Location
}

Write-Step 'Preparing .env'
$envFile = Join-Path $script:RepoRoot '.env'
if (-not (Test-Path $envFile)) {
    Copy-Item (Join-Path $script:RepoRoot '.env.example') $envFile
    Write-Host 'Created .env from .env.example'
} else {
    Write-Host '.env already exists - left untouched'
}

Write-Host ''
Write-Host 'Setup complete. Next: scripts\check.ps1 to verify, scripts\dev.ps1 to run.' -ForegroundColor Green
