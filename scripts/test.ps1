<#
.SYNOPSIS
    Run backend (pytest, with coverage) and frontend (vitest) tests.
.PARAMETER Only
    'backend', 'frontend' or 'both' (default).
#>
[CmdletBinding()]
param(
    [ValidateSet('both', 'backend', 'frontend')]
    [string]$Only = 'both'
)

. "$PSScriptRoot/_common.ps1"
Set-Location $script:RepoRoot

if ($Only -in 'both', 'backend') {
    Write-Step 'pytest'
    Invoke-VenvModule -Module pytest -Arguments @('--cov')
}
if ($Only -in 'both', 'frontend') {
    Write-Step 'vitest'
    Invoke-Npm -Arguments @('test')
}
