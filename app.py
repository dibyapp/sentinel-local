"""Sentinel Local: private host monitoring for Windows, Linux, and macOS."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import copy
import datetime as dt
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import platform
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit
import webbrowser

from engine import BehaviorModel, assess, rows, wifi_fields, timestamp, scan_events
from backends import make_backend
from privacy import state_directory, public_report
from version import __version__
from guidance import system_profile, next_steps, assistant_handoff
from ai_evidence import build_evidence, REASONS
from ai_providers import run_review, provider_options, PROVIDERS, ProviderError
from ai_integrations import load_profiles

ROOT = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent))
DATA = state_directory()
HIDDEN = getattr(subprocess, 'CREATE_NO_WINDOW', 0)


def utcnow():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def save_json(path, value):
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding='utf-8')
    if os.name != 'nt':
        temp.chmod(0o600)
    temp.replace(path)


def read_json(path, default):
    try:
        return json.loads(path.read_text(encoding='utf-8-sig'))
    except (OSError, ValueError):
        return default


def powershell(script, *arguments, timeout=180):
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File',
                             str(ROOT / 'scripts' / script), *arguments],
                            capture_output=True, encoding='utf-8', errors='replace',
                            creationflags=HIDDEN, timeout=timeout)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout or 'Windows command failed').strip()[:3000])
    return json.loads(result.stdout.lstrip('\ufeff').strip())


def wifi_adapter(snapshot):
    collected = timestamp(snapshot.get('collectedAt'))
    if not collected or (dt.datetime.now(dt.timezone.utc) - collected.astimezone(dt.timezone.utc)).total_seconds() > 240:
        raise ValueError('Refresh the security snapshot before Wi-Fi discovery.')
    fields = wifi_fields(snapshot.get('wifiRaw'))
    if fields.get('state', '').lower() != 'connected':
        raise ValueError('Connected Wi-Fi could not be verified. Network discovery was not started.')
    name = fields.get('name')
    adapter = next((a for a in rows(snapshot.get('addresses')) if a.get('interface') == name), None)
    if not adapter:
        raise ValueError('Wi-Fi adapter IPv4 configuration is unavailable.')
    address = next((a for a in rows(adapter.get('addresses')) if a.get('IPAddress')), None)
    if not address:
        raise ValueError('No Wi-Fi IPv4 address found.')
    interface = ipaddress.ip_interface(f"{address['IPAddress']}/{address['PrefixLength']}")
    private_ranges = [ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
    if not any(interface.ip in network for network in private_ranges):
        raise ValueError('Discovery is restricted to private home-network IPv4 addresses.')
    network = interface.network if interface.network.prefixlen >= 24 else ipaddress.ip_network(f'{interface.ip}/24', strict=False)
    gateways = [str(ipaddress.ip_address(g)) for g in rows(adapter.get('gateways')) if g and ipaddress.ip_address(g) in interface.network]
    return adapter, interface, network, gateways


def network_scan(snapshot):
    adapter, interface, network, gateways = wifi_adapter(snapshot)
    found = {str(interface.ip): {'ip': str(interface.ip), 'kind': 'This computer'}}
    def ping(address):
        try:
            system = snapshot.get('platform') or platform.system()
            if system == 'Windows':
                command = ['ping.exe', '-4', '-n', '1', '-w', '250', '-S', str(interface.ip), str(address)]
            elif system == 'Darwin':
                command = ['ping', '-n', '-c', '1', '-W', '500', '-S', str(interface.ip), str(address)]
            else:
                command = ['ping', '-n', '-c', '1', '-W', '1', '-I', str(interface.ip), str(address)]
            result = subprocess.run(command, capture_output=True, timeout=2, creationflags=HIDDEN)
            return str(address) if result.returncode == 0 and b'TTL=' in result.stdout.upper() else None
        except (OSError, subprocess.TimeoutExpired):
            return None
    with ThreadPoolExecutor(max_workers=16) as pool:
        for address in pool.map(ping, [a for a in network.hosts() if a != interface.ip]):
            if address:
                found[address] = {'ip': address, 'kind': 'Responds to ping'}
    for neighbor in rows(snapshot.get('neighbors')):
        try:
            neighbor_ip = ipaddress.ip_address(neighbor.get('IPAddress', ''))
            in_range = neighbor_ip in network and neighbor_ip not in (network.network_address, network.broadcast_address)
        except ValueError:
            in_range = False
        if neighbor.get('InterfaceIndex') == adapter.get('index') and in_range and neighbor.get('LinkLayerAddress') not in ('FF-FF-FF-FF-FF-FF', '00-00-00-00-00-00'):
            item = found.setdefault(neighbor['IPAddress'], {'ip': neighbor['IPAddress'], 'kind': 'Neighbor cache (may be offline)'})
            item['mac'] = neighbor.get('LinkLayerAddress')
    services = []
    ports = {21: 'FTP', 22: 'SSH', 23: 'Telnet', 80: 'HTTP', 443: 'HTTPS', 445: 'SMB', 3389: 'Remote Desktop', 8080: 'HTTP alternate', 8443: 'HTTPS alternate'}
    def probe(pair):
        gateway, port = pair
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                sock.bind((str(interface.ip), 0))
                sock.connect((gateway, port))
                return {'ip': gateway, 'port': port, 'service': ports[port]}
        except OSError:
            return None
    with ThreadPoolExecutor(max_workers=8) as pool:
        services = [s for s in pool.map(probe, [(g, p) for g in gateways for p in ports]) if s]
    for gateway in gateways:
        found.setdefault(gateway, {'ip': gateway})['kind'] = 'Router / gateway'
    return {'completedAt': utcnow(), 'interface': adapter['interface'], 'subnet': str(network),
            'ssid': wifi_fields(snapshot.get('wifiRaw')).get('ssid'),
            'devices': sorted(found.values(), key=lambda d: int(ipaddress.ip_address(d['ip']))),
            'routerServices': services,
            'coverage': 'ICMP discovery, neighbor cache, and nine TCP connection checks on the local router. Silent devices can be missed. Router firmware, passwords, and traffic contents are not inspected.'}


class Agent:
    def __init__(self, interval=60, data_dir=DATA, backend=None, scan_roots=(), ai_config=None):
        self.data_dir = data_dir
        data_dir.mkdir(exist_ok=True, parents=True)
        if os.name != 'nt':
            data_dir.chmod(0o700)
        self.backend = backend or make_backend(lambda *args, **kwargs: powershell(*args, **kwargs), scan_roots)
        self.ai_profiles = load_profiles(ai_config, PROVIDERS)
        self.configuration = hashlib.sha256(json.dumps({'aiProfiles': self.ai_profiles, 'scanRoots': [str(p) for p in scan_roots], 'interval': interval}, sort_keys=True).encode()).hexdigest()
        self.system = system_profile()
        self.ai_preview = None
        self.lock = threading.RLock()
        self.collect_lock = threading.Lock()
        self.wakeup = threading.Event()
        self.stop = threading.Event()
        self.interval = interval
        self.model = BehaviorModel(read_json(data_dir / 'model.json', None))
        self.state = {'snapshot': None, 'findings': [], 'jobs': [], 'network': read_json(data_dir / 'network.json', None),
                      'history': read_json(data_dir / 'history.json', []), 'monitoring': True,
                      'alertHistory': read_json(data_dir / 'alert-history.json', []),
                      'aiReviews': read_json(data_dir / 'ai-reviews.json', [])[-20:],
                      'aiChecks': read_json(data_dir / 'ai-checks.json', [])[-20:],
                      'startedAt': utcnow(), 'lastError': None, 'collecting': False}
        for review in self.state['aiReviews'] + self.state['aiChecks']:
            if review.get('status') == 'running':
                review.update(status='unverified', error='The previous AI review was interrupted; no result was verified.')
        for job in read_json(data_dir / 'jobs.json', [])[-100:]:
            if job.get('status') == 'running':
                job.update(status='unverified', error='The monitor restarted while this action was running. Verify its result in Windows Security.', finishedAt=utcnow())
            self.state['jobs'].append(job)

    def view(self):
        with self.lock:
            result = copy.deepcopy(self.state)
            result['model'] = {'samples': self.model.state['samples'], 'warmup': 20,
                               'processes': len(self.model.state['processes']), 'ready': self.model.state['samples'] >= 20,
                               'paused': bool(result['snapshot']) and (result['snapshot'].get('processes') is None or result['snapshot'].get('connections') is None)}
            result['interval'] = self.interval
            result['defenderScans'] = scan_events(result.get('snapshot') or {})
            result['jobs'] = result['jobs'][-20:]
            result['capabilities'] = self.backend.capabilities()
            result['version'] = __version__
            existing = {f['id'] for f in result['findings']}
            result['findings'].extend(f for f in self.scanner_findings() if f['id'] not in existing)
            # Recent validated AI advisories are visible in the main status,
            # but never train the baseline or become a malware verdict.
            completed = [r for r in result['aiReviews'] if r.get('status') == 'completed']
            if completed:
                review = completed[-1]
                finished = timestamp(review.get('finishedAt'))
                if finished and 0 <= (dt.datetime.now(dt.timezone.utc) - finished.astimezone(dt.timezone.utc)).total_seconds() <= 240:
                    for finding in rows((review.get('result') or {}).get('result', {}).get('findings')):
                        reason = finding.get('reason_code')
                        if reason not in REASONS:
                            continue
                        label = (review.get('aliases') or {}).get(finding.get('evidence_id'), {}).get('name', 'Anonymous observation')
                        title, advice = REASONS[reason]
                        result['findings'].append({'id': 'ai:' + review['id'] + ':' + finding['evidence_id'] + ':' + reason,
                                                  'severity': 'review', 'source': 'AI advisory review', 'title': title,
                                                  'detail': f'{label}: {advice} Sampled observation; this is not a malware verdict.'})
            result['system'] = copy.deepcopy(self.system)
            result['guide'] = next_steps(result, result['capabilities'])
            result['directAiReview'] = True
            return result

    def assistant_prompt(self):
        with self.lock:
            return assistant_handoff(self.state, self.model)

    def signature_status(self, paths):
        if self.backend.name != 'Windows' or not paths:
            return {}
        try:
            request = [{'id': index, 'path': path} for index, path in enumerate(paths)]
            response = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(ROOT / 'scripts' / 'verify-signatures.ps1')],
                                      input=json.dumps(request), capture_output=True, encoding='utf-8', errors='replace',
                                      timeout=20, creationflags=HIDDEN)
            if response.returncode:
                return {}
            values = rows(json.loads(response.stdout.lstrip('\ufeff')))
            return {paths[item['id']]: item['status'] for item in values if type(item.get('id')) is int and 0 <= item['id'] < len(paths) and item.get('status') in ('valid', 'unsigned', 'invalid', 'unknown')}
        except Exception:
            return {}

    def ai_evidence(self):
        with self.lock:
            state = copy.deepcopy(self.state)
            model = BehaviorModel(copy.deepcopy(self.model.state))
        return build_evidence(state, model, self.signature_status if self.backend.name == 'Windows' else None)

    def preview_ai_review(self, provider):
        if provider not in (*PROVIDERS, *self.ai_profiles):
            raise ValueError('Unknown AI provider.')
        packet, aliases = self.ai_evidence()
        with self.lock:
            token = secrets.token_urlsafe(24)
            self.ai_preview = {'provider': provider, 'token': token, 'created': time.monotonic(), 'packet': packet, 'aliases': aliases}
        return {'evidence': packet, 'previewToken': token}

    def launch_ai_review(self, provider='ollama', model='', allow_cloud=False, preview_token=''):
        if provider not in (*PROVIDERS, *self.ai_profiles, 'auto') or not isinstance(model, str) or len(model) > 120 or type(allow_cloud) is not bool:
            raise ValueError('Invalid AI review options.')
        if provider not in ('auto', 'ollama') and not allow_cloud:
            raise ValueError('Select a cloud provider and explicitly consent to send anonymous indicators first.')
        with self.lock:
            if any(r.get('status') == 'running' for r in self.state['aiReviews'] + self.state['aiChecks']):
                raise ValueError('An AI review is already running.')
            frozen_preview = None
            if provider not in ('auto', 'ollama'):
                preview = self.ai_preview
                if not isinstance(preview_token, str) or not preview or preview['provider'] != provider or not secrets.compare_digest(preview['token'].encode(), preview_token.encode()) or time.monotonic() - preview['created'] > 240:
                    raise ValueError('Preview the exact anonymous evidence for this provider before starting a cloud review.')
                frozen_preview = copy.deepcopy(preview)
                self.ai_preview = None
            review = {'id': secrets.token_hex(8), 'provider': 'ollama' if provider == 'auto' else provider,
                      'status': 'running', 'startedAt': utcnow()}
            self.state['aiReviews'].append(review)
            self.state['aiReviews'] = self.state['aiReviews'][-20:]
            save_json(self.data_dir / 'ai-reviews.json', self.state['aiReviews'])
        def work():
            try:
                if frozen_preview:
                    packet, aliases = frozen_preview['packet'], frozen_preview['aliases']
                else:
                    self.collect()
                    packet, aliases = self.ai_evidence()
                options = {'allow_cloud': allow_cloud}
                if self.ai_profiles: options['profiles'] = self.ai_profiles
                if provider == 'gemini': options['gemini_home'] = self.data_dir / 'gemini-profile'
                result = run_review(provider, model, packet, **options)
                with self.lock:
                    review.update(status='completed', result=result, aliases=aliases, coverage=packet['coverage'], finishedAt=utcnow())
            except ProviderError as exc:
                logging.exception('AI provider contract failed')
                with self.lock:
                    review.update(status='unverified', error=str(exc), errorCode=exc.code, finishedAt=utcnow())
            except Exception:
                logging.exception('AI review failed; result was not accepted')
                with self.lock:
                    review.update(status='unverified', error='The selected AI review failed, timed out, or returned an unsupported result. No other provider was tried. No malware verdict is available.', finishedAt=utcnow())
            finally:
                with self.lock:
                    save_json(self.data_dir / 'ai-reviews.json', self.state['aiReviews'])
        self.ai_worker = threading.Thread(target=work, daemon=True, name='ai-security-review')
        self.ai_worker.start()
        return copy.deepcopy(review)

    def launch_ai_check(self, provider='ollama', model='', allow_cloud=False):
        if provider not in (*PROVIDERS, *self.ai_profiles, 'auto') or not isinstance(model, str) or len(model) > 120 or type(allow_cloud) is not bool:
            raise ValueError('Invalid AI connection test options.')
        if provider not in ('ollama', 'auto') and not allow_cloud:
            raise ValueError('Explicitly consent to this provider test first. Only fictional evidence will be sent.')
        with self.lock:
            if any(r.get('status') == 'running' for r in self.state['aiReviews'] + self.state['aiChecks']):
                raise ValueError('An AI request is already running.')
            check = {'id': secrets.token_hex(8), 'provider': 'ollama' if provider == 'auto' else provider,
                     'status': 'running', 'fictionalEvidenceOnly': True, 'startedAt': utcnow()}
            self.state['aiChecks'].append(check)
            self.state['aiChecks'] = self.state['aiChecks'][-20:]
            save_json(self.data_dir / 'ai-checks.json', self.state['aiChecks'])
        def work():
            try:
                result = run_review(provider, model, fictional_ai_packet(), allow_cloud=allow_cloud,
                                    profiles=self.ai_profiles, gemini_home=self.data_dir / 'gemini-profile')
                with self.lock:
                    check.update(status='completed', cloudUsed=result['cloudUsed'], message='Connection and structured review verified using fictional evidence only.', finishedAt=utcnow())
            except Exception as exc:
                logging.exception('Fictional provider test failed')
                with self.lock:
                    check.update(status='unverified', errorCode=exc.code if isinstance(exc, ProviderError) else 'unsupported_result',
                                 error=str(exc) if isinstance(exc, ProviderError) else 'No verified connection result. Check the selected model and provider setup; raw errors remain local.', finishedAt=utcnow())
            finally:
                with self.lock: save_json(self.data_dir / 'ai-checks.json', self.state['aiChecks'])
        threading.Thread(target=work, daemon=True, name='ai-connection-check').start()
        return copy.deepcopy(check)

    def scanner_findings(self):
        findings = []
        for job in self.state['jobs']:
            result = job.get('result') or {}
            if job.get('status') == 'completed' and result.get('engine') == 'ClamAV' and result.get('exitCode') == 1:
                findings.append({'id': 'scan:' + job['id'], 'severity': 'critical', 'source': 'ClamAV',
                                 'title': 'ClamAV scan reported detections',
                                 'detail': 'Review the local scan results. Detected files were not removed or quarantined by Sentinel; this historical scan result does not establish their current state.'})
        return findings

    def collect(self):
        if not self.collect_lock.acquire(blocking=False):
            return
        with self.lock:
            self.state['collecting'] = True
        try:
            snapshot = self.backend.collect()
            with self.lock:
                findings = assess(snapshot, self.model) + self.scanner_findings()
                old = {(f['id'], f['detail']) for f in self.state['findings']}
                for finding in findings:
                    if (finding['id'], finding['detail']) not in old:
                        self.state['alertHistory'].append({**finding, 'observedAt': utcnow()})
                self.state['alertHistory'] = self.state['alertHistory'][-500:]
                self.state.update(snapshot=snapshot, findings=findings, lastError=None)
                self.state['history'].append({'time': utcnow(), 'processes': len(rows(snapshot.get('processes'))),
                                              'connections': len(rows(snapshot.get('connections'))), 'findings': len(findings)})
                self.state['history'] = self.state['history'][-720:]
                save_json(self.data_dir / 'model.json', self.model.state)
                save_json(self.data_dir / 'history.json', self.state['history'])
                save_json(self.data_dir / 'alert-history.json', self.state['alertHistory'])
                save_json(self.data_dir / 'latest-report.json', self.private_report())
        except Exception as exc:
            logging.exception('Collection failed')
            with self.lock:
                self.state['lastError'] = str(exc)
        finally:
            with self.lock:
                self.state['collecting'] = False
            self.collect_lock.release()

    def report(self):
        with self.lock:
            return public_report(self.state, self.model)

    def private_report(self):
        with self.lock:
            result = copy.deepcopy(self.state)
        snapshot = result.get('snapshot') or {}
        # Reports omit full process command lines and startup user names.
        for process in rows(snapshot.get('processes')):
            process.pop('CommandLine', None)
        for item in rows(snapshot.get('startup')):
            item.pop('User', None)
        result['exportedAt'] = utcnow()
        result['scope'] = 'PRIVATE LOCAL DATA. Sampled host monitoring and optional Wi-Fi audit; never include this file in contributions or release artifacts.'
        return result

    def monitor(self):
        while not self.stop.is_set():
            self.wakeup.clear()
            self.collect()
            self.wakeup.wait(self.interval)

    def launch_job(self, action):
        if not isinstance(action, str) or action not in ('quick', 'full', 'update', 'network', 'scan'):
            raise ValueError('Unknown action')
        if action not in self.backend.capabilities()['actions']:
            raise ValueError('This action is unavailable on this platform or is not configured. Check Monitor health.')
        with self.lock:
            group = 'network' if action == 'network' else 'defender'
            if any(j['status'] == 'running' and j['group'] == group for j in self.state['jobs']):
                raise ValueError('An action in this group is already running.')
            snapshot = copy.deepcopy(self.state['snapshot'])
            if action in ('quick', 'full') and any(s.get('status') == 'running' for s in scan_events(snapshot or {})):
                raise ValueError('Defender already reports a scan in progress. Wait for its completion event.')
            if action == 'network':
                wifi_adapter(snapshot or {})
            job = {'id': secrets.token_hex(8), 'action': action, 'group': group, 'status': 'running', 'startedAt': utcnow()}
            self.state['jobs'].append(job)
            self.state['jobs'] = self.state['jobs'][-100:]
            save_json(self.data_dir / 'jobs.json', self.state['jobs'])
        def work():
            try:
                if action == 'network':
                    result = network_scan(snapshot)
                    with self.lock:
                        self.state['network'] = result
                        save_json(self.data_dir / 'network.json', result)
                else:
                    result = self.backend.action(action)
                    if action in ('quick', 'full'):
                        verification = self.backend.collect()
                        scans = [s for s in scan_events(verification)
                                 if timestamp(s.get('startedAt')) and timestamp(s['startedAt']) >= timestamp(job['startedAt']) - dt.timedelta(seconds=3)]
                        if not scans or scans[0].get('status') != 'completed':
                            with self.lock:
                                job.update(status='unverified', result=result,
                                           error='Windows returned from the scan command, but no matching completed-scan event was verified. Check Defender scan history.', finishedAt=utcnow())
                            return
                        result['verifiedScan'] = scans[0]
                with self.lock:
                    job.update(status='completed', result=result, finishedAt=utcnow())
            except subprocess.TimeoutExpired:
                with self.lock:
                    job.update(status='unverified', error='Command exceeded the time limit. Defender may still be scanning; check Windows Security.', finishedAt=utcnow())
            except Exception as exc:
                with self.lock:
                    job.update(status='failed', error=str(exc), finishedAt=utcnow())
            finally:
                with self.lock:
                    save_json(self.data_dir / 'jobs.json', self.state['jobs'])
                self.wakeup.set()
        threading.Thread(target=work, daemon=True, name=f'action-{action}').start()
        return copy.deepcopy(job)


def run_requested_scan(agent, selection):
    """Only explicit quick/selected scans; CLI results never expose raw output."""
    agent.collect()
    if agent.state['lastError'] or not agent.state['snapshot']:
        return {'status': 'unverified', 'reason': 'Refresh failed; no scan was started.', 'summary': agent.report()}
    action = 'quick' if selection == 'quick' else 'scan'
    try:
        started = agent.launch_job(action)
    except ValueError:
        return {'status': 'unavailable', 'reason': 'Scan is unavailable, not configured, or already running. Check the local dashboard.', 'summary': agent.report()}
    while True:
        with agent.lock:
            job = next(j for j in agent.state['jobs'] if j['id'] == started['id'])
            if job['status'] != 'running':
                job = copy.deepcopy(job)
                break
        time.sleep(0.2)
    agent.collect()
    result = job.get('result') or {}
    status = job['status'] if job['status'] in ('completed', 'failed', 'unverified') else 'unverified'
    return {'status': status, 'scan': selection,
            'detectionsReported': result.get('exitCode') == 1 if result.get('engine') == 'ClamAV' else None,
            'reason': 'Review native protection history and scan coverage; completion does not certify a clean computer.' if status == 'completed' else 'Scan completion was not verified. Review local scan history; raw errors remain local.',
            'summary': agent.report()}


def fictional_ai_packet():
    return {'schema': 'sentinel-ai-evidence-v1', 'summary': {'platform': 'unknown', 'privacy': 'Fictional fixture; no host observations'},
            'evidence': [{'id': 'E001', 'kind': 'protection', 'indicators': {'protection_off': True}}],
            'coverage': {'allFilesScanned': False, 'fictionalEvidenceOnly': True}}


class Server(ThreadingHTTPServer):
    daemon_threads = True
    def server_bind(self):
        if os.name == 'nt':
            self.allow_reuse_address = False
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def __init__(self, address, agent):
        super().__init__(address, Handler)
        self.agent = agent
        self.token = secrets.token_urlsafe(32)
        self.origin = f'http://127.0.0.1:{self.server_port}'


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *args):
        pass

    def respond(self, status, body, content_type='application/json; charset=utf-8'):
        payload = body if isinstance(body, bytes) else json.dumps(body).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(payload)

    def permitted(self, auth=False, mutation=False):
        expected = f'127.0.0.1:{self.server.server_port}'
        if self.headers.get('Host') != expected:
            self.respond(403, {'error': 'Invalid host'})
            return False
        origin = self.headers.get('Origin')
        if origin and origin != self.server.origin or mutation and origin != self.server.origin:
            self.respond(403, {'error': 'Invalid origin'})
            return False
        if auth and not secrets.compare_digest(self.headers.get('X-Sentinel-Token', '').encode('utf-8'), self.server.token.encode('utf-8')):
            self.respond(401, {'error': 'Open the dashboard using Sentinel --open or a local launcher.'})
            return False
        return True

    def do_GET(self):
        path = urlsplit(self.path).path
        if not self.permitted(auth=path.startswith('/api/')):
            return
        if path == '/api/status':
            self.respond(200, self.server.agent.view())
        elif path == '/api/report':
            self.respond(200, self.server.agent.report())
        elif path == '/api/assistant':
            self.respond(200, self.server.agent.assistant_prompt())
        elif path == '/api/ai/options':
            self.respond(200, provider_options(self.server.agent.ai_profiles) if self.server.agent.ai_profiles else provider_options())
        elif path in ('/', '/app.js', '/style.css'):
            filename, mime = {'/': ('index.html', 'text/html; charset=utf-8'), '/app.js': ('app.js', 'text/javascript; charset=utf-8'), '/style.css': ('style.css', 'text/css; charset=utf-8')}[path]
            self.respond(200, (ROOT / 'static' / filename).read_bytes(), mime)
        elif path == '/help/ai':
            self.respond(200, (ROOT / 'docs' / 'AI_REVIEW.md').read_bytes(), 'text/plain; charset=utf-8')
        else:
            self.respond(404, {'error': 'Not found'})

    def do_POST(self):
        if not self.permitted(auth=True, mutation=True):
            return
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 1024:
                raise ValueError('Invalid request size')
            body = json.loads(self.rfile.read(size))
            if not isinstance(body, dict):
                raise ValueError('Expected a JSON object')
            path = urlsplit(self.path).path
            if path == '/api/action':
                self.respond(202, self.server.agent.launch_job(body.get('action')))
            elif path == '/api/refresh':
                self.server.agent.wakeup.set()
                self.respond(202, {'status': 'queued'})
            elif path == '/api/ai/review':
                self.respond(202, self.server.agent.launch_ai_review(body.get('provider', 'ollama'), body.get('model', ''), body.get('allowCloud', False), body.get('previewToken', '')))
            elif path == '/api/ai/preview':
                self.respond(200, self.server.agent.preview_ai_review(body.get('provider', 'ollama')))
            elif path == '/api/ai/check':
                self.respond(202, self.server.agent.launch_ai_check(body.get('provider', 'ollama'), body.get('model', ''), body.get('allowCloud', False)))
            else:
                self.respond(404, {'error': 'Not found'})
        except (ValueError, TypeError, AttributeError) as exc:
            self.respond(400, {'error': str(exc)})


def dashboard_server(agent, data_dir, port, open_browser):
    """Reuse only this release; preserve older listeners and explicit port choices."""
    from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs): return None
    saved = read_json(data_dir / 'instance.json', {})
    saved_port = saved.get('port')
    if type(saved_port) is int and 1 <= saved_port <= 65535 and (port is None or saved_port == port):
        try:
            request = Request(f'http://127.0.0.1:{saved_port}/api/status', headers={'X-Sentinel-Token': saved['token']})
            with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=3) as response:
                status = json.loads(response.read(1_000_001))
            if status.get('version') == __version__:
                if saved.get('configuration') != agent.configuration:
                    raise SystemExit('A monitor with different settings is already running in this private data directory. Close it before changing settings, or select a separate --data-dir and --port.')
                if open_browser: webbrowser.open(f'http://127.0.0.1:{saved_port}/#token=' + saved['token'])
                return None
        except Exception:
            pass
    try:
        return Server(('127.0.0.1', 8877 if port is None else port), agent)
    except OSError:
        if port is not None: raise SystemExit('Port is unavailable. Use a different --port.')
        return Server(('127.0.0.1', 0), agent)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='version', version=f'Sentinel Local {__version__}')
    parser.add_argument('--port', type=int, default=None, help='Loopback dashboard port; automatically select a free port if the default is occupied')
    parser.add_argument('--interval', type=int, default=60)
    parser.add_argument('--open', action='store_true')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--once', action='store_true')
    mode.add_argument('--diagnose', action='store_true', help='Read host status once and print a sharing-safe summary; no scan or service changes')
    mode.add_argument('--self-test', action='store_true', help='Run synthetic smoke tests without scanning host files or starting a monitor')
    mode.add_argument('--assistant-prompt', action='store_true', help='Print a sharing-safe prompt for any AI assistant; no assistant is contacted')
    mode.add_argument('--scan', choices=('quick', 'selected'), help='Explicit one-shot native scan; quick is Windows, selected uses configured ClamAV folders')
    mode.add_argument('--ai-review', help='AI provider ID: auto, ollama, codex, claude, gemini, or a configured profile; auto stays local')
    mode.add_argument('--ai-check', help='Test one AI provider using fictional evidence only, without collecting this computer')
    parser.add_argument('--ai-config', type=Path, help='Explicit private JSON profiles for other model servers or trusted headless wrappers')
    parser.add_argument('--ai-model', default='', help='Existing downloaded Ollama model; no downloads are started')
    parser.add_argument('--allow-cloud-ai', action='store_true', help='Explicitly send anonymous indicators to the selected cloud CLI; account usage may apply')
    parser.add_argument('--data-dir', type=Path, default=DATA, help='Private runtime directory; default is outside the source checkout')
    parser.add_argument('--scan-root', action='append', default=[], help='Absolute folder to scan with optional ClamAV on Linux/macOS; repeat for multiple folders')
    args = parser.parse_args()
    if args.port is not None and not 1 <= args.port <= 65535:
        parser.error('Port must be between 1 and 65535.')
    if args.ai_review and args.ai_review not in ('auto', 'ollama') and not args.allow_cloud_ai:
        parser.error('Cloud AI needs --allow-cloud-ai. Use --ai-review ollama for local analysis.')
    if (args.ai_model or args.allow_cloud_ai) and not (args.ai_review or args.ai_check):
        parser.error('AI options require --ai-review or --ai-check.')
    if args.ai_check and args.ai_check not in ('auto', 'ollama') and not args.allow_cloud_ai:
        parser.error('Testing this AI tool needs --allow-cloud-ai; only fictional evidence will be sent.')
    if args.scan or args.ai_review or args.ai_check or args.assistant_prompt or args.diagnose or args.once or args.self_test:
        if args.open:
            parser.error('--open is for the dashboard; use it separately from a one-shot command.')
    elif getattr(sys, 'frozen', False) and len(sys.argv) == 1:
        args.open = True
    if args.self_test:
        from selftest import run
        result = run()
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result['passed'] else 1)
    data_dir = args.data_dir.expanduser().resolve()
    data_dir.mkdir(exist_ok=True, parents=True)
    if os.name != 'nt':
        data_dir.chmod(0o700)
    logging.basicConfig(handlers=[RotatingFileHandler(data_dir / 'agent.log', maxBytes=2_000_000, backupCount=2)],
                        level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    try:
        agent = Agent(interval=max(30, args.interval), data_dir=data_dir, scan_roots=args.scan_root, ai_config=args.ai_config)
    except ValueError as exc:
        parser.error(str(exc))
    selected = args.ai_review or args.ai_check
    if selected and selected not in (*PROVIDERS, *agent.ai_profiles, 'auto'):
        parser.error('Unknown AI provider ID. Configure a private profile with --ai-config.')
    if args.ai_check:
        packet = fictional_ai_packet()
        try:
            result = run_review(args.ai_check, args.ai_model, packet, allow_cloud=args.allow_cloud_ai,
                                profiles=agent.ai_profiles, gemini_home=data_dir / 'gemini-profile')
            value = {'status': 'completed', 'fictionalEvidenceOnly': True, 'hostCollected': False, 'result': result}
        except Exception as exc:
            logging.exception('Fictional provider test failed')
            value = {'status': 'unverified', 'fictionalEvidenceOnly': True, 'hostCollected': False,
                     'errorCode': exc.code if isinstance(exc, ProviderError) else 'unsupported_result',
                     'error': str(exc) if isinstance(exc, ProviderError) else 'The selected tool returned no verified result. Review its setup and private local log.'}
        print(json.dumps(value, indent=2))
        raise SystemExit(0 if value['status'] == 'completed' else 1)
    if args.ai_review:
        preview_token = ''
        if args.ai_review not in ('auto', 'ollama'):
            agent.collect()
            preview_token = agent.preview_ai_review(args.ai_review)['previewToken']
        review = agent.launch_ai_review(args.ai_review, args.ai_model, args.allow_cloud_ai, preview_token)
        while True:
            with agent.lock:
                finished = next(r for r in agent.state['aiReviews'] if r['id'] == review['id'])
                if finished['status'] != 'running':
                    result = copy.deepcopy(finished)
                    break
            time.sleep(0.2)
        agent.ai_worker.join(timeout=5)
        result.pop('aliases', None)
        for key in ('id', 'startedAt', 'finishedAt'): result.pop(key, None)
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result['status'] == 'completed' else 1)
    if args.scan:
        result = run_requested_scan(agent, args.scan)
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result['status'] == 'completed' else 1)
    if args.assistant_prompt:
        agent.collect()
        print(agent.assistant_prompt()['prompt'])
        raise SystemExit(1 if agent.state['lastError'] else 0)
    if args.once or args.diagnose:
        agent.collect()
        print(json.dumps(agent.report(), indent=2))
        raise SystemExit(1 if agent.state['lastError'] else 0)
    server = dashboard_server(agent, data_dir, args.port, args.open)
    if server is None: return
    url = server.origin + '/#token=' + server.token
    save_json(data_dir / 'instance.json', {'port': server.server_port, 'token': server.token, 'url': url, 'pid': os.getpid(), 'configuration': agent.configuration})
    threading.Thread(target=agent.monitor, daemon=True, name='monitor').start()
    if args.open:
        webbrowser.open(url)
    print(f'Sentinel is monitoring at {server.origin}. Run again with --open to open its dashboard.')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        agent.stop.set()
        agent.wakeup.set()
        server.server_close()


if __name__ == '__main__':
    main()
