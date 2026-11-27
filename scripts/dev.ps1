<#
.SYNOPSIS
    Start the development servers (FastAPI backend + Vite frontend).
.PARAMETER Only
    Start just one side: 'backend' or 'frontend'. Default starts both, each in its own window.
#>
[CmdletBinding()]
param(
    [ValidateSet('both', 'backend', 'frontend')]
    [string]$Only = 'both'
)

. "$PSScriptRoot/_common.ps1"
Set-Location $script:RepoRoot

function Start-Backend {
    Assert-Venv
    # Honour PASSAUDIT_HOST / PASSAUDIT_PORT from .env by asking the app's own settings.
    $addr = & $script:VenvPython -c 'from passaudit.config import get_settings as g; s = g(); print(s.host, s.port)'
    if ($LASTEXITCODE -ne 0) { throw 'Could not load settings (check your .env).' }
    $bindHost, $bindPort = ($addr -split '\s+')
    Write-Step "Backend: http://${bindHost}:${bindPort} (docs at /docs in development)"
    Invoke-Native -FilePath $script:VenvPython -Arguments @(
        '-m', 'uvicorn', 'passaudit.main:app',
        '--host', $bindHost, '--port', $bindPort,
        '--reload', '--reload-dir', 'backend/src',
        # uvicorn's access log records query strings; the app logs its own sanitized lines.
        '--no-access-log'
    )
}

function Start-Frontend {
    Write-Step 'Frontend: http://127.0.0.1:5173'
    Invoke-Npm -Arguments @('run', 'dev')
}

switch ($Only) {
    'backend' { Start-Backend }
    'frontend' { Start-Frontend }
    'both' {
        Assert-Venv
        Assert-FrontendDeps
        $shell = if (Get-Command pwsh -ErrorAction SilentlyContinue) { 'pwsh' } else { 'powershell' }
        foreach ($target in 'backend', 'frontend') {
            Start-Process -FilePath $shell -WorkingDirectory $script:RepoRoot -ArgumentList @(
                '-NoExit', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                '-File', (Join-Path $PSScriptRoot 'dev.ps1'), '-Only', $target
            )
        }
        Write-Host 'Started backend and frontend in separate windows. Close them to stop.'
    }
}
