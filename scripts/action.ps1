param([ValidateSet('quick','full','update')][string]$Action)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
switch ($Action) {
    'quick' { Start-MpScan -ScanType QuickScan }
    'full' { Start-MpScan -ScanType FullScan }
    'update' { Update-MpSignature }
}
[pscustomobject]@{ action = $Action; finishedAt = (Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json -Compress
