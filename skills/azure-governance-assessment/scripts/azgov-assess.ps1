#!/usr/bin/env pwsh
# Windows / PowerShell launcher for the azgov_assess engine (Python 3.9+, standard library only).
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$py = if ($env:AZGOV_PYTHON) { $env:AZGOV_PYTHON } else {
    @('python3', 'python', 'py') | Where-Object { Get-Command $_ -ErrorAction SilentlyContinue } | Select-Object -First 1
}
if (-not $py) { Write-Error 'azgov-assess: Python 3.9+ is required (set AZGOV_PYTHON to override)'; exit 3 }
$env:PYTHONPATH = if ($env:PYTHONPATH) { "$here$([IO.Path]::PathSeparator)$env:PYTHONPATH" } else { $here }
$env:PYTHONDONTWRITEBYTECODE = '1'
& $py -m azgov_assess @args
exit $LASTEXITCODE
