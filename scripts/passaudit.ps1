<#
.SYNOPSIS
    Run the PassAudit command-line interface from the project virtual environment.
.DESCRIPTION
    Equivalent to `python -m passaudit ...`. Use this when Windows Application Control blocks
    the generated passaudit.exe launcher (see docs/adr/0002). All arguments are passed through
    unchanged and the exit code is preserved. Piped input reaches `--stdin` / `batch -`.
.EXAMPLE
    .\scripts\passaudit.ps1 audit
.EXAMPLE
    'correct horse battery staple' | .\scripts\passaudit.ps1 audit --stdin
.EXAMPLE
    .\scripts\passaudit.ps1 batch passwords.txt --format json --output report.json
#>

. "$PSScriptRoot/_common.ps1"
Assert-Venv

# Send piped text to the CLI as UTF-8 without a BOM (Windows PowerShell 5.1 defaults to ASCII).
$OutputEncoding = New-Object System.Text.UTF8Encoding $false

if ($MyInvocation.ExpectingInput) {
    $input | & $script:VenvPython -m passaudit @args
}
else {
    & $script:VenvPython -m passaudit @args
}
exit $LASTEXITCODE
