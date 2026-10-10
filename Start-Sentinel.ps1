$ErrorActionPreference = 'Stop'
$taskPython = Join-Path $PSScriptRoot '.venv\Scripts\pythonw.exe'
if (-not (Test-Path -LiteralPath $taskPython -PathType Leaf)) {
    $taskPython = (Get-Command pythonw.exe -ErrorAction SilentlyContinue).Source
}
if (-not $taskPython) {
    $taskPython = (Get-Command python.exe -ErrorAction Stop).Source
}
$taskCheckPython = $taskPython -replace 'pythonw\.exe$', 'python.exe'
& $taskCheckPython -c 'import psutil' 2>$null
if ($LASTEXITCODE -ne 0) {
    throw 'A required dependency is missing. In this folder run: python -m pip install -r requirements.txt, then open Sentinel again.'
}
$taskApp = Join-Path $PSScriptRoot 'app.py'
Start-Process -FilePath $taskPython -ArgumentList @(('"' + $taskApp + '"'), '--open') -WorkingDirectory $PSScriptRoot -WindowStyle Hidden
