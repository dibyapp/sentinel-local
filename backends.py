"""Native desktop adapters. Missing permissions stay unknown, never healthy."""
import datetime as dt
import ipaddress
import json
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess

HIDDEN = getattr(subprocess, 'CREATE_NO_WINDOW', 0)


def run_command(argv, timeout=20):
    return subprocess.run(argv, capture_output=True, text=True, encoding='utf-8', errors='replace',
                          timeout=timeout, creationflags=HIDDEN)


def checked(argv, timeout=20):
    result = run_command(argv, timeout)
    if result.returncode:
        raise RuntimeError(f'{Path(argv[0]).name} returned exit code {result.returncode}; this source is unavailable or needs permission.')
    return result.stdout


def split_nmcli(line):
    """NetworkManager escapes colons and backslashes in its terse output."""
    values, current, escaped = [], '', False
    for char in line:
        if escaped:
            current += char; escaped = False
        elif char == '\\':
            escaped = True
        elif char == ':':
            values.append(current); current = ''
        else:
            current += char
    values.append(current)
    return values


class WindowsBackend:
    name = 'Windows'
    def __init__(self, runner):
        self.runner = runner

    def capabilities(self):
        return {'platform': self.name, 'engine': 'Microsoft Defender', 'actions': ['quick', 'full', 'update', 'network'],
                'realtime': 'Provided by Microsoft Defender; state is verified in each snapshot',
                'scanScope': 'Defender quick scan or full local computer scan'}

    def collect(self):
        snapshot = self.runner('collect.ps1')
        snapshot['platform'] = self.name
        snapshot['capabilities'] = self.capabilities()
        return snapshot

    def action(self, action):
        return self.runner('action.ps1', '-Action', action, timeout=14400)


class PosixBackend:
    def __init__(self, system, scan_roots=()):
        self.name = system
        self.scan_roots = []
        for value in scan_roots:
            path = Path(value).expanduser()
            if not path.is_absolute() or not path.is_dir():
                raise ValueError('Scan roots must be absolute existing directories.')
            self.scan_roots.append(path.resolve())

    def capabilities(self):
        scanner = shutil.which('clamscan')
        updater = shutil.which('freshclam')
        actions = ['network']
        if scanner and self.scan_roots:
            actions.append('scan')
        if updater:
            actions.append('update')
        return {'platform': self.name, 'engine': 'ClamAV' if scanner else 'No on-demand scanner configured',
                'actions': actions, 'scannerInstalled': bool(scanner), 'scanConfigured': bool(self.scan_roots),
                'realtime': 'Not supplied by Sentinel. Existing OS protections and separately configured tools remain responsible.',
                'scanScope': 'Explicitly selected folders only; no automatic full-disk scan',
                'connectionCoverage': 'macOS needs root for system TCP visibility; Linux may omit connections owned by other users.'}

    def collect(self):
        import psutil
        result = {'platform': self.name, 'collectedAt': dt.datetime.now(dt.timezone.utc).isoformat(),
                  'errors': [], 'coverageNotes': [], 'capabilities': self.capabilities(),
                  'defender': None, 'preferences': None, 'threats': [], 'detections': [], 'events': [], 'profiles': [],
                  'processes': [], 'connections': None, 'listeners': None, 'startup': [], 'neighbors': [], 'addresses': [], 'firewall': None}
        def section(name, function):
            try:
                result[name] = function()
            except Exception as exc:
                result['errors'].append(f'{name}: unavailable ({type(exc).__name__}); check tool availability and permissions.')
        denied = 0
        for process in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'ppid'], ad_value=None):
            try:
                item = process.info
                if item['exe'] is None:
                    denied += 1
                result['processes'].append({'ProcessId': item['pid'], 'Name': item['name'] or 'unknown',
                                            'ExecutablePath': item['exe'], 'CommandLine': ' '.join(item['cmdline'] or []),
                                            'ParentProcessId': item['ppid']})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                denied += 1
        if denied:
            result['coverageNotes'].append(f'{denied} processes lacked complete metadata or exited during collection.')
        def connections():
            established, listeners = [], []
            for connection in psutil.net_connections(kind='tcp'):
                status = getattr(connection.status, 'value', connection.status)
                entry = {'LocalAddress': connection.laddr.ip, 'LocalPort': connection.laddr.port,
                         'OwningProcess': connection.pid}
                if status == psutil.CONN_ESTABLISHED and connection.raddr:
                    entry.update(RemoteAddress=connection.raddr.ip, RemotePort=connection.raddr.port)
                    established.append(entry)
                elif status == psutil.CONN_LISTEN:
                    listeners.append(entry)
            result['listeners'] = listeners
            return established
        section('connections', connections)
        if self.name == 'Linux' and hasattr(__import__('os'), 'geteuid') and __import__('os').geteuid() != 0:
            result['coverageNotes'].append('Unprivileged Linux connection inventory may omit sockets owned by other users.')
        routes = {}
        if self.name == 'Linux':
            try:
                for route in json.loads(checked(['ip', '-j', '-4', 'route', 'show', 'default'])):
                    if route.get('gateway'):
                        routes.setdefault(route['dev'], []).append(route['gateway'])
            except Exception:
                result['errors'].append('routes: IPv4 gateway discovery unavailable; install iproute2 or check permissions.')
        elif self.name == 'Darwin':
            try:
                output = checked(['route', '-n', 'get', 'default'])
                fields = dict(re.findall(r'^\s*(interface|gateway):\s*(\S+)', output, re.M))
                if fields.get('interface') and fields.get('gateway'):
                    routes[fields['interface']] = [fields['gateway']]
            except Exception:
                result['errors'].append('routes: default gateway discovery unavailable.')
        for name, entries in psutil.net_if_addrs().items():
            addresses = []
            for entry in entries:
                if entry.family == socket.AF_INET and entry.netmask:
                    try:
                        addresses.append({'IPAddress': entry.address, 'PrefixLength': ipaddress.ip_network(f'0.0.0.0/{entry.netmask}').prefixlen})
                    except ValueError:
                        pass
            if addresses:
                try:
                    index = socket.if_nametoindex(name)
                except OSError:
                    index = None
                result['addresses'].append({'interface': name, 'index': index, 'addresses': addresses, 'gateways': routes.get(name, []), 'dns': []})
        section('wifi', lambda: self.wifi(result))
        result['wifiRaw'] = '\n'.join(f'{key} : {value}' for key, value in (result.get('wifi') or {}).items())
        section('firewall', self.firewall)
        if self.name == 'Linux':
            def neighbors():
                found = []
                indexes = {a['interface']: a['index'] for a in result['addresses']}
                for item in json.loads(checked(['ip', '-j', '-4', 'neigh', 'show'])):
                    if item.get('lladdr'):
                        found.append({'IPAddress': item['dst'], 'LinkLayerAddress': item['lladdr'].upper().replace(':', '-'),
                                      'InterfaceIndex': indexes.get(item['dev']), 'State': 'Neighbor cache'})
                return found
            section('neighbors', neighbors)
            root = Path.home() / '.config' / 'autostart'
            result['startup'] = [{'Name': p.stem, 'Location': str(p)} for p in root.glob('*.desktop')]
        else:
            def neighbors():
                found = []
                indexes = {a['interface']: a['index'] for a in result['addresses']}
                for line in checked(['arp', '-an']).splitlines():
                    match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]+) on (\S+)', line, re.I)
                    if match:
                        mac = '-'.join(part.zfill(2).upper() for part in match[2].split(':'))
                        found.append({'IPAddress': match[1], 'LinkLayerAddress': mac, 'InterfaceIndex': indexes.get(match[3]), 'State': 'Neighbor cache'})
                return found
            section('neighbors', neighbors)
            root = Path.home() / 'Library' / 'LaunchAgents'
            result['startup'] = [{'Name': p.stem, 'Location': str(p)} for p in root.glob('*.plist')]
            def native_protection():
                gatekeeper = checked(['spctl', '--status']).strip()
                integrity = checked(['csrutil', 'status']).strip()
                return {'GatekeeperEnabled': gatekeeper == 'assessments enabled',
                        'SystemIntegrityProtectionEnabled': 'status: enabled' in integrity.lower(),
                        'XProtectStatus': 'Not independently verified by Sentinel'}
            section('nativeProtection', native_protection)
        return result

    def wifi(self, snapshot):
        if self.name == 'Linux':
            interfaces = [a['interface'] for a in snapshot['addresses'] if (Path('/sys/class/net') / a['interface'] / 'wireless').exists()]
            for name in interfaces:
                if not shutil.which('nmcli'):
                    continue
                output = checked(['nmcli', '-t', '--escape', 'yes', '-f', 'IN-USE,SSID,SECURITY,SIGNAL', 'device', 'wifi', 'list', 'ifname', name, '--rescan', 'no'])
                for line in output.splitlines():
                    values = split_nmcli(line)
                    if len(values) >= 4 and values[0] == '*':
                        security = values[2]
                        return {'Name': name, 'State': 'connected', 'SSID': values[1],
                                'Authentication': 'Open' if security in ('', '--') else security,
                                'Cipher': 'Not verified', 'Signal': values[3] + '%',
                                'Source': 'NetworkManager cached Wi-Fi security advertisement'}
            snapshot['coverageNotes'].append('Connected Wi-Fi/security could not be verified; network discovery is unavailable. Ethernet, VM, and VPN interfaces are not substituted.')
            return {}
        ports = checked(['networksetup', '-listallhardwareports'])
        match = re.search(r'Hardware Port: (?:Wi-Fi|AirPort)\s+Device: (\S+)', ports)
        if not match:
            return {}
        name = match[1]
        output = checked(['networksetup', '-getairportnetwork', name])
        match = re.search(r'Current Wi-Fi Network: (.+)', output)
        if not match:
            snapshot['coverageNotes'].append('macOS did not disclose a connected Wi-Fi network; Sentinel does not request privacy permission automatically.')
            return {}
        fields = {'Name': name, 'State': 'connected', 'SSID': match[1].strip(), 'Authentication': 'Not verified', 'Cipher': 'Not verified'}
        # The public system_profiler schema varies by OS version: read documented
        # report data defensively and leave unknown fields unverified.
        try:
            report = json.loads(checked(['system_profiler', 'SPAirPortDataType', '-json'], timeout=30))
            def find(value):
                if isinstance(value, dict):
                    info = value.get('spairport_current_network_information')
                    if isinstance(info, dict) and info.get('_name') == fields['SSID']:
                        return info
                    for child in value.values():
                        found = find(child)
                        if found:
                            return found
                elif isinstance(value, list):
                    for child in value:
                        found = find(child)
                        if found:
                            return found
                return None
            current = find(report)
            if current and current.get('spairport_security_mode'):
                fields['Authentication'] = current['spairport_security_mode']
        except Exception:
            snapshot['coverageNotes'].append('Wi-Fi authentication metadata is unavailable on this macOS version.')
        return fields

    def firewall(self):
        if self.name == 'Darwin':
            output = checked(['/usr/libexec/ApplicationFirewall/socketfilterfw', '--getglobalstate'])
            if 'State = 1' in output:
                return [{'Name': 'macOS application firewall', 'Enabled': True}]
            if 'State = 0' in output:
                return [{'Name': 'macOS application firewall', 'Enabled': False}]
            raise RuntimeError('Unrecognized firewall state')
        if shutil.which('ufw'):
            output = checked(['ufw', 'status'])
            if 'Status: active' in output:
                return [{'Name': 'UFW', 'Enabled': True}]
            if 'Status: inactive' in output:
                return [{'Name': 'UFW', 'Enabled': False}]
        if shutil.which('firewall-cmd'):
            output = checked(['firewall-cmd', '--state'])
            if output.strip() == 'running':
                return [{'Name': 'firewalld service (rules not audited)', 'Enabled': True}]
        raise RuntimeError('No supported readable firewall status source')

    def action(self, action):
        if action == 'update':
            tool = shutil.which('freshclam')
            if not tool:
                raise ValueError('ClamAV definition updater is not installed.')
            output = checked([tool, '--stdout'], timeout=900)
            return {'engine': 'ClamAV', 'action': 'update', 'output': output[-12000:]}
        if action != 'scan' or not self.scan_roots:
            raise ValueError('Choose scan folders with --scan-root and install ClamAV before requesting a scan.')
        tool = shutil.which('clamscan')
        if not tool:
            raise ValueError('ClamAV is not installed.')
        command = [tool, '--recursive', '--infected', '--cross-fs=no', '--follow-dir-symlinks=0',
                   '--follow-file-symlinks=0', '--alert-exceeds-max=yes', *[str(p) for p in self.scan_roots]]
        result = run_command(command, timeout=14400)
        if result.returncode not in (0, 1):
            raise RuntimeError(f'ClamAV returned exit code {result.returncode}; scan coverage is incomplete. Check permissions and definitions.')
        count = re.search(r'Infected files:\s*(\d+)', result.stdout)
        scanned = re.search(r'Scanned files:\s*(\d+)', result.stdout)
        return {'engine': 'ClamAV', 'action': 'scan', 'detectionCount': int(count[1]) if count else None,
                'scannedFiles': int(scanned[1]) if scanned else None, 'exitCode': result.returncode,
                'verdict': 'detections' if result.returncode == 1 else 'no_detections_in_scanned_content',
                'output': result.stdout[-20000:], 'errors': result.stderr[-6000:],
                'coverage': 'Selected folders only, no symlink following, no crossing mounted filesystems. Permission errors and engine limits can omit content. No files are removed or quarantined.'}


def make_backend(windows_runner, scan_roots=(), system=None):
    selected = system or platform.system()
    if selected == 'Windows':
        return WindowsBackend(windows_runner)
    if selected in ('Linux', 'Darwin'):
        return PosixBackend(selected, scan_roots)
    raise RuntimeError('Supported desktop systems: Windows, Linux, and macOS. This OS is not supported.')
