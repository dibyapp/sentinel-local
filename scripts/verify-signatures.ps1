$ErrorActionPreference = 'Stop'
$taskEntries = [Console]::In.ReadToEnd() | ConvertFrom-Json
$taskResults = @()
foreach ($taskEntry in @($taskEntries) | Select-Object -First 12) {
    $taskStatus = 'unknown'
    try {
        $taskSignature = Get-AuthenticodeSignature -LiteralPath $taskEntry.path -ErrorAction Stop
        switch ([string]$taskSignature.Status) {
            'Valid' { $taskStatus = 'valid' }
            'NotSigned' { $taskStatus = 'unsigned' }
            'HashMismatch' { $taskStatus = 'invalid' }
        }
    } catch { }
    $taskResults += @{ id = $taskEntry.id; status = $taskStatus }
}
ConvertTo-Json -InputObject @($taskResults) -Compress
