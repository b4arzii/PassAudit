<#
.SYNOPSIS
    Lint backend (ruff) and frontend (eslint). Use -Fix to apply safe autofixes.
#>
[CmdletBinding()]
param([switch]$Fix)

. "$PSScriptRoot/_common.ps1"
Set-Location $script:RepoRoot

Write-Step 'ruff check'
$ruffArgs = @('check', '.')
if ($Fix) { $ruffArgs += '--fix' }
Invoke-VenvModule -Module ruff -Arguments $ruffArgs

Write-Step 'eslint'
Invoke-Npm -Arguments @('run', $(if ($Fix) { 'lint:fix' } else { 'lint' }))
