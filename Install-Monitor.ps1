param([switch]$EnableAutostart)
$ErrorActionPreference = 'Stop'
$taskPython = (Get-Command pythonw.exe -ErrorAction SilentlyContinue).Source
if (-not $taskPython) { $taskPython = (Get-Command python.exe -ErrorAction Stop).Source }
$taskShell = New-Object -ComObject WScript.Shell
function New-SentinelShortcut($taskDestination, [bool]$taskOpen) {
    $taskShortcut = $taskShell.CreateShortcut($taskDestination)
    $taskShortcut.TargetPath = $taskPython
    $taskShortcut.Arguments = '"' + (Join-Path $PSScriptRoot 'app.py') + '"' + $(if ($taskOpen) { ' --open' } else { '' })
    $taskShortcut.WorkingDirectory = $PSScriptRoot
    $taskShortcut.WindowStyle = 7
    $taskShortcut.Description = 'Sentinel local Defender and Wi-Fi security monitor'
    $taskShortcut.Save()
}
New-SentinelShortcut (Join-Path $PSScriptRoot 'Sentinel.lnk') $true
if ($EnableAutostart) {
    $taskStartup = [Environment]::GetFolderPath('Startup')
    New-SentinelShortcut (Join-Path $taskStartup 'Sentinel Local Monitor.lnk') $false
    Write-Output 'Monitoring will start at Windows sign-in for this user.'
}
Write-Output 'Created Sentinel.lnk. Double-click it to open the dashboard.'
