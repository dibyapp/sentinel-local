"""Executable smoke checks with fictional observations only."""
import datetime as dt
import http.client
import json
from pathlib import Path
import tempfile
import threading


def run():
    from app import Agent, Server, wifi_adapter, ROOT
    from backends import WindowsBackend
    from engine import BehaviorModel, assess
    checks = {}
    snapshot = {'platform': 'Windows', 'collectedAt': dt.datetime.now(dt.timezone.utc).isoformat(),
                'defender': {'AntivirusEnabled': True, 'RealTimeProtectionEnabled': True, 'BehaviorMonitorEnabled': True},
                'processes': [], 'connections': [], 'errors': [], 'firewall': [{'Name': 'Test', 'Enabled': True}],
                'wifiRaw': 'Name : test-wifi\nState : connected\nSSID : FICTIONAL-NETWORK',
                'addresses': [{'interface': 'test-wifi', 'index': 1, 'addresses': [{'IPAddress': '192.168.50.2', 'PrefixLength': 24}], 'gateways': ['192.168.50.1']}]}
    checks['bundled_assets'] = all((ROOT / name).is_file() for name in ('static/index.html', 'static/app.js', 'static/style.css', 'scripts/collect.ps1', 'scripts/action.ps1', 'scripts/verify-signatures.ps1', 'docs/AI_REVIEW.md'))
    checks['healthy_fixture'] = not assess(snapshot, BehaviorModel())
    unsafe = dict(snapshot, defender={'RealTimeProtectionEnabled': False})
    checks['disabled_protection_detected'] = any(f['severity'] == 'critical' for f in assess(unsafe, BehaviorModel()))
    checks['wifi_scope'] = str(wifi_adapter(snapshot)[2]) == '192.168.50.0/24'
    snapshot['processes'] = [{'Name': 'fictional.exe', 'CommandLine': 'FAKE-PRIVATE-CANARY', 'ExecutablePath': '/fictional/private/location'}]
    with tempfile.TemporaryDirectory(prefix='sentinel-test-') as directory:
        agent = Agent(data_dir=Path(directory), backend=WindowsBackend(lambda *args, **kwargs: snapshot))
        agent.state['snapshot'] = snapshot
        checks['report_redaction'] = 'FAKE-PRIVATE-CANARY' not in json.dumps(agent.report()) and '/fictional/private/location' not in json.dumps(agent.report())
        handoff = agent.assistant_prompt()
        checks['assistant_handoff_redaction'] = not handoff['connected'] and 'FAKE-PRIVATE-CANARY' not in handoff['prompt'] and '/fictional/private/location' not in handoff['prompt']
        checks['guided_status_available'] = bool(agent.view()['guide']['steps'])
        from ai_evidence import build_evidence, validate_result
        packet, _ = build_evidence(agent.state, agent.model)
        checks['direct_ai_redaction'] = 'FAKE-PRIVATE-CANARY' not in json.dumps(packet) and '/fictional/private/location' not in json.dumps(packet)
        try:
            validate_result({'assessment': 'review', 'findings': [{'evidence_id': 'E999', 'severity': 'review', 'reason_code': 'encoded_command', 'next_step': 'verify_app'}]}, packet)
            checks['unsupported_ai_rejected'] = False
        except ValueError:
            checks['unsupported_ai_rejected'] = True
        server = Server(('127.0.0.1', 0), agent)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
            connection.request('GET', '/api/status')
            response = connection.getresponse(); checks['unauthenticated_denied'] = response.status == 401; response.read(); connection.close()
            connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
            connection.request('GET', '/api/status', headers={'X-Sentinel-Token': server.token})
            response = connection.getresponse(); checks['authenticated_allowed'] = response.status == 200; response.read(); connection.close()
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)
    return {'passed': all(checks.values()), 'checks': checks, 'scope': 'Synthetic functionality checks; not malware efficacy certification.'}
