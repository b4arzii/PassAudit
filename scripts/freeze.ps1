<#
.SYNOPSIS
    Regenerate backend/requirements.lock.txt from the current virtual environment.
#>
[CmdletBinding()]
param()

. "$PSScriptRoot/_common.ps1"
Set-Location $script:RepoRoot
Assert-Venv

$header = @(
    '# Snapshot of the verified-working Python environment (pip freeze).',
    '# Reference only: pyproject.toml is the source of truth. Regenerate with scripts/freeze.ps1 after changing deps.'
)
$packages = & $script:VenvPython -m pip freeze --exclude-editable | Sort-Object { $_.ToLowerInvariant() }
($header + $packages) | Set-Content -Path (Join-Path $script:RepoRoot 'backend\requirements.lock.txt') -Encoding utf8
Write-Host "Wrote backend\requirements.lock.txt ($($packages.Count) packages)"
