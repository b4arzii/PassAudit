<#
.SYNOPSIS
    Full quality gate: format check, lint, type-check, tests, frontend build.
    Run this before every commit. Add -Audit to include security/dependency audits.
#>
[CmdletBinding()]
param([switch]$Audit)

. "$PSScriptRoot/_common.ps1"
Set-Location $script:RepoRoot

& "$PSScriptRoot/format.ps1" -Check
& "$PSScriptRoot/lint.ps1"
& "$PSScriptRoot/typecheck.ps1"
& "$PSScriptRoot/test.ps1"

Write-Step 'frontend build'
Invoke-Npm -Arguments @('run', 'build')

if ($Audit) { & "$PSScriptRoot/audit.ps1" }

Write-Host ''
Write-Host 'All checks passed.' -ForegroundColor Green
