<#
.SYNOPSIS
    Security checks: bandit (static analysis) and dependency vulnerability audits.
.DESCRIPTION
    pip-audit and npm audit need network access to vulnerability databases.
#>
[CmdletBinding()]
param()

. "$PSScriptRoot/_common.ps1"
Set-Location $script:RepoRoot

Write-Step 'bandit (backend static analysis)'
Invoke-VenvModule -Module bandit -Arguments @('-q', '-c', 'pyproject.toml', '-r', 'backend/src')

Write-Step 'pip-audit (backend dependencies)'
Invoke-VenvModule -Module pip_audit -Arguments @('--skip-editable')

Write-Step 'npm audit (frontend dependencies)'
Invoke-Npm -Arguments @('run', 'audit')
