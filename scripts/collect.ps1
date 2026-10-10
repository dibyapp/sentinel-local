$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$result = [ordered]@{ collectedAt = (Get-Date).ToUniversalTime().ToString('o'); errors = @() }
function Read-Section($name, [scriptblock]$work) {
    try { $result[$name] = & $work } catch { $result[$name] = $null; $result.errors += "$name : $($_.Exception.Message)" }
}
Read-Section 'defender' {
    Get-MpComputerStatus | Select-Object AMServiceEnabled,AMRunningMode,AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,IsTamperProtected,AntivirusSignatureLastUpdated,AntivirusSignatureVersion,QuickScanStartTime,QuickScanEndTime,FullScanStartTime,FullScanEndTime,RebootRequired
}
Read-Section 'preferences' { Get-MpPreference | Select-Object MAPSReporting,SubmitSamplesConsent,PUAProtection,EnableControlledFolderAccess,DisableRealtimeMonitoring,DisableBehaviorMonitoring }
Read-Section 'firewall' { @(Get-NetFirewallProfile | Select-Object Name,Enabled) }
Read-Section 'profiles' { @(Get-NetConnectionProfile | Select-Object Name,InterfaceAlias,InterfaceIndex,NetworkCategory,IPv4Connectivity) }
Read-Section 'addresses' {
    @(Get-NetIPConfiguration | ForEach-Object {
        [pscustomobject]@{ interface = $_.InterfaceAlias; index = $_.InterfaceIndex; addresses = @($_.IPv4Address | Select-Object IPAddress,PrefixLength); gateways = @($_.IPv4DefaultGateway.NextHop); dns = @($_.DNSServer.ServerAddresses) }
    })
}
Read-Section 'wifiRaw' { (netsh wlan show interfaces | Out-String) }
Read-Section 'neighbors' { @(Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.State -in @('Reachable','Stale','Delay','Probe','Permanent') } | Select-Object IPAddress,LinkLayerAddress,State,InterfaceIndex) }
Read-Section 'processes' { @(Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ExecutablePath,CommandLine,ParentProcessId) }
Read-Section 'connections' { @(Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess) }
Read-Section 'listeners' { @(Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess) }
Read-Section 'startup' { @(Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User) }
Read-Section 'threats' { @(Get-MpThreat | Select-Object ThreatID,ThreatName,IsActive,DidThreatExecute,SeverityID,Resources) }
Read-Section 'detections' { @(Get-MpThreatDetection | Select-Object -First 30 ThreatID,InitialDetectionTime,LastThreatStatusChangeTime,ActionSuccess,ThreatStatusID,Resources) }
Read-Section 'events' {
    $filter = @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = @(1000,1001,1002,1116,1117,5001); StartTime = (Get-Date).AddDays(-1) }
    try { @(Get-WinEvent -FilterHashtable $filter -MaxEvents 30 | Select-Object Id,TimeCreated,Message) }
    catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { @() } else { throw } }
}
$result | ConvertTo-Json -Depth 8 -Compress
