<#
.SYNOPSIS
    Type-check backend (mypy --strict) and frontend (tsc).
#>
[CmdletBinding()]
param()

. "$PSScriptRoot/_common.ps1"
Set-Location $script:RepoRoot

Write-Step 'mypy'
Invoke-VenvModule -Module mypy

Write-Step 'tsc'
Invoke-Npm -Arguments @('run', 'typecheck')
