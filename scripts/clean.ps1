<#
.SYNOPSIS
    Remove build artefacts and caches. Use -All to also remove .venv and node_modules.
#>
[CmdletBinding()]
param([switch]$All)

. "$PSScriptRoot/_common.ps1"
Set-Location $script:RepoRoot

# Forward slashes work on every platform in PowerShell paths.
$targets = @(
    '.pytest_cache', '.mypy_cache', '.ruff_cache', 'htmlcov', '.coverage', 'coverage.xml',
    'frontend/dist', 'frontend/coverage', 'frontend/node_modules/.tmp'
)
if ($All) { $targets += @('.venv', 'frontend/node_modules') }

foreach ($t in $targets) {
    $path = Join-Path $script:RepoRoot $t
    if (Test-Path $path) {
        Remove-Item -Recurse -Force $path
        Write-Host "Removed $t"
    }
}
$sep = [regex]::Escape([string][System.IO.Path]::DirectorySeparatorChar)
Get-ChildItem -Path $script:RepoRoot -Recurse -Directory -Filter '__pycache__' -Force |
    Where-Object { $_.FullName -notmatch "$sep(\.venv|node_modules)$sep" } |
    ForEach-Object { Remove-Item -Recurse -Force $_.FullName; Write-Host "Removed $($_.FullName.Substring($script:RepoRoot.Length + 1))" }
