param([switch]$DisableAutostart)
$ErrorActionPreference = 'Stop'
$taskInstancePath = Join-Path $env:LOCALAPPDATA 'SentinelLocal\instance.json'
if (-not (Test-Path -LiteralPath $taskInstancePath)) { $taskInstancePath = Join-Path $PSScriptRoot 'data\instance.json' }
$taskAppPath = Join-Path $PSScriptRoot 'app.py'
if (Test-Path -LiteralPath $taskInstancePath) {
    $taskInstance = Get-Content -LiteralPath $taskInstancePath -Raw | ConvertFrom-Json
    $taskAgentProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $([int]$taskInstance.pid)"
    $taskQuotedPath = '"' + $taskAppPath + '"'
    $taskBarePathPattern = '(?i)(?:^|\s)' + [regex]::Escape($taskAppPath) + '(?:\s|$)'
    $taskMatchingApp = $taskAgentProcess -and ($taskAgentProcess.CommandLine.Contains($taskQuotedPath) -or $taskAgentProcess.CommandLine -match $taskBarePathPattern)
    if ($taskMatchingApp -and $taskAgentProcess.Name -in @('python.exe','pythonw.exe')) {
        Stop-Process -Id $taskAgentProcess.ProcessId
        Write-Output 'Sentinel monitor stopped. Defender remains active.'
    }
}
if ($DisableAutostart) {
    $taskShortcutPath = Join-Path ([Environment]::GetFolderPath('Startup')) 'Sentinel Local Monitor.lnk'
    if (Test-Path -LiteralPath $taskShortcutPath) {
        $taskShell = New-Object -ComObject WScript.Shell
        $taskShortcut = $taskShell.CreateShortcut($taskShortcutPath)
        if ($taskShortcut.Arguments.Contains('"' + $taskAppPath + '"')) {
            Remove-Item -LiteralPath $taskShortcutPath
            Write-Output 'Sentinel automatic startup disabled.'
        }
    }
}
