"""Local security assessment and explainable online statistical anomaly model."""
import datetime as dt
import ipaddress
import math
import re


def rows(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def timestamp(value):
    if not value:
        return None
    if isinstance(value, str) and value.startswith('/Date('):
        match = re.search(r'/Date\((-?\d+)', value)
        return dt.datetime.fromtimestamp(int(match[1]) / 1000, dt.timezone.utc) if match else None
    try:
        return dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (ValueError, TypeError):
        return None


def wifi_fields(raw):
    fields = {}
    for line in (raw or '').splitlines():
        if ':' in line:
            key, value = line.split(':', 1)
            fields[key.strip().lower()] = value.strip()
    return fields


def public_address(value):
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def scan_events(snapshot):
    """Join Defender starts and terminal events by scan ID, newest first."""
    scans = {}
    for event in sorted(rows(snapshot.get('events')), key=lambda e: str(e.get('TimeCreated', ''))):
        if event.get('Id') not in (1000, 1001, 1002):
            continue
        match = re.search(r'\{[0-9a-fA-F-]{36}\}', event.get('Message') or '')
        if not match:
            continue
        key = match.group(0)
        record = scans.setdefault(key, {'id': key})
        if event['Id'] == 1000:
            record.update(startedAt=event.get('TimeCreated'), status='running')
        else:
            record.update(finishedAt=event.get('TimeCreated'), status='completed' if event['Id'] == 1001 else 'stopped')
    return sorted(scans.values(), key=lambda s: str(s.get('startedAt', s.get('finishedAt', ''))), reverse=True)


class BehaviorModel:
    """Per-process running means and frequencies. Signals are advisory, not verdicts."""
    def __init__(self, state=None):
        self.state = state or {'samples': 0, 'processes': {}, 'gatewayMacs': {}}

    def inspect(self, snapshot):
        alerts = []
        if snapshot.get('processes') is None or snapshot.get('connections') is None:
            # Missing sensors are not observations of zero activity. Do not
            # corrupt the baseline or advance warmup when TCP/process access
            # is unavailable (common on unprivileged macOS/Linux).
            return alerts
        trained = self.state['samples'] >= 20
        by_pid = {}
        for connection in rows(snapshot.get('connections')):
            if public_address(connection.get('RemoteAddress', '')):
                by_pid.setdefault(connection.get('OwningProcess'), []).append(connection)
        seen = set()
        for process in rows(snapshot.get('processes')):
            key = (process.get('ExecutablePath') or process.get('Name') or 'unknown').lower()
            if key in seen:
                continue
            seen.add(key)
            connections = [c for p in rows(snapshot.get('processes'))
                           if (p.get('ExecutablePath') or p.get('Name') or 'unknown').lower() == key
                           for c in by_pid.get(p.get('ProcessId'), [])]
            count = len(connections)
            record = self.state['processes'].get(key, {'n': 0, 'mean': 0.0, 'm2': 0.0, 'ports': {}})
            reasons = []
            score = 0
            if trained and record['n'] == 0 and count:
                reasons.append('First observed process making a public internet connection after baseline learning.')
                score += 30
            if record['n'] >= 20:
                deviation = math.sqrt(record['m2'] / max(1, record['n'] - 1))
                if count > record['mean'] + max(8, 4 * deviation):
                    reasons.append(f"Internet connection count {count} is unusually high; learned average {record['mean']:.1f}.")
                    score += 45
            unusual_ports = sorted({c.get('RemotePort') for c in connections
                                    if c.get('RemotePort') not in (80, 443) and str(c.get('RemotePort')) not in record['ports']})
            if trained and unusual_ports:
                reasons.append(f'New destination ports for this process: {unusual_ports}.')
                score += 20
            path = (process.get('ExecutablePath') or '').lower().replace('/', '\\')
            if count and any(segment in path for segment in ('\\downloads\\', '\\temp\\', '\\tmp\\', '\\private\\var\\folders\\')):
                reasons.append('Program connects to the internet from a Downloads or temporary folder. Legitimate installers can do this.')
                score += 25
            command = (process.get('CommandLine') or '').lower()
            if re.search(r'\bpowershell(?:\.exe)?\b', process.get('Name', '').lower()) and re.search(r'-(?:enc(?:odedcommand)?|e)\s+\S+', command):
                reasons.append('PowerShell uses an encoded command; review its origin.')
                score += 45
            if score >= 40:
                alerts.append({'id': 'behavior:' + key, 'severity': 'review', 'title': process.get('Name') or key,
                               'detail': ' '.join(reasons), 'score': min(100, score), 'source': 'Local behavior model'})
                # Do not absorb flagged behavior into a trusted baseline automatically.
                continue
            record['n'] += 1
            delta = count - record['mean']
            record['mean'] += delta / record['n']
            record['m2'] += delta * (count - record['mean'])
            for port in {str(c.get('RemotePort')) for c in connections}:
                record['ports'][port] = record['ports'].get(port, 0) + 1
            if len(self.state['processes']) < 5000 or key in self.state['processes']:
                self.state['processes'][key] = record
        self.state['samples'] += 1
        return alerts


def assess(snapshot, model):
    findings = []
    def add(key, severity, title, detail):
        findings.append({'id': key, 'severity': severity, 'title': title, 'detail': detail, 'source': 'Security checks'})
    defender = snapshot.get('defender') or {}
    for field, label in [('AntivirusEnabled', 'Antivirus'), ('RealTimeProtectionEnabled', 'Real-time protection'), ('BehaviorMonitorEnabled', 'Behavior monitoring')]:
        if defender.get(field) is False:
            add(field, 'critical', label + ' is off', 'Open Windows Security and enable this protection.')
    system = snapshot.get('platform', 'Windows')
    if not defender and system == 'Windows':
        add('defender-unavailable', 'warning', 'Defender status unavailable', 'Protection could not be verified. Review the collection errors.')
    for profile in rows(snapshot.get('firewall')):
        if profile.get('Enabled') is False or profile.get('Enabled') == 0:
            add('firewall:' + profile['Name'], 'critical', profile['Name'] + ' firewall is off', 'Enable this profile in Windows Security.')
    updated = timestamp(defender.get('AntivirusSignatureLastUpdated'))
    if updated and (dt.datetime.now(dt.timezone.utc) - updated.astimezone(dt.timezone.utc)).total_seconds() > 172800:
        add('signatures', 'warning', 'Malware definitions are older than 48 hours', 'Use Update definitions when internet access is available.')
    for threat in rows(snapshot.get('threats')):
        if threat.get('IsActive'):
            add('threat:' + str(threat.get('ThreatID')), 'critical', threat.get('ThreatName', 'Active Defender detection'), 'Defender reports an active threat. Review Windows Security → Protection history.')
    preferences = snapshot.get('preferences') or {}
    if system in ('Linux', 'Darwin'):
        capabilities = snapshot.get('capabilities') or {}
        if not capabilities.get('scannerInstalled'):
            add('scanner-unavailable', 'info', 'Optional on-demand scanner is unavailable', 'Install ClamAV and select scan folders if you want file scans. Sentinel provides sampled host monitoring; it does not supply real-time malware blocking on this platform.')
        for field, title in [('GatekeeperEnabled', 'Gatekeeper'), ('SystemIntegrityProtectionEnabled', 'System Integrity Protection')]:
            if (snapshot.get('nativeProtection') or {}).get(field) is False:
                add(field, 'warning', title + ' is disabled', 'Review this native macOS protection. Sentinel never changes it automatically.')
    if preferences.get('PUAProtection') == 0:
        add('pua', 'info', 'Unwanted-app blocking is off', 'Consider enabling reputation-based protection in Windows Security.')
    fields = wifi_fields(snapshot.get('wifiRaw'))
    auth = fields.get('authentication', '')
    cipher = fields.get('cipher', '')
    if auth and ('open' in auth.lower() or 'wep' in auth.lower() or 'wep' in cipher.lower() or 'tkip' in cipher.lower()):
        add('wifi-encryption', 'critical', 'Weak Wi-Fi security', f'Authentication: {auth}; cipher: {cipher}. Configure your router for WPA2-AES or WPA3.')
    for adapter in rows(snapshot.get('addresses')):
        for gateway in rows(adapter.get('gateways')):
            neighbor = next((n for n in rows(snapshot.get('neighbors')) if n.get('IPAddress') == gateway and n.get('InterfaceIndex') == adapter.get('index')), None)
            if neighbor and neighbor.get('LinkLayerAddress') and neighbor['LinkLayerAddress'] != '00-00-00-00-00-00':
                baseline_key = f"{adapter.get('index')}:{fields.get('ssid', '')}:{gateway}"
                known = model.state['gatewayMacs'].get(baseline_key)
                mac = neighbor['LinkLayerAddress']
                if known and known != mac:
                    add('gateway-mac:' + baseline_key, 'warning', 'Gateway hardware address changed', f'{gateway}: {known} → {mac}. Router replacement or mesh roaming can cause this; verify your router.')
                elif not known:
                    model.state['gatewayMacs'][baseline_key] = mac
    findings.extend(model.inspect(snapshot))
    return findings
