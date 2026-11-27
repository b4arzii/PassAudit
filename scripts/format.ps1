<#
.SYNOPSIS
    Format backend (ruff format) and frontend (prettier). Use -Check to verify only.
#>
[CmdletBinding()]
param([switch]$Check)

. "$PSScriptRoot/_common.ps1"
Set-Location $script:RepoRoot

Write-Step 'ruff format'
$ruffArgs = @('format', '.')
if ($Check) { $ruffArgs += '--check' }
Invoke-VenvModule -Module ruff -Arguments $ruffArgs

Write-Step 'prettier'
Invoke-Npm -Arguments @('run', $(if ($Check) { 'format:check' } else { 'format' }))
