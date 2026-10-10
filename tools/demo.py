"""Reproducible fictional dashboard. No host collection, scans, or AI requests."""
import argparse
import datetime as dt
import json
from pathlib import Path
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import app
from ai_evidence import validate_result
from backends import WindowsBackend


def snapshot():
    return {'platform': 'Windows', 'collectedAt': dt.datetime.now(dt.timezone.utc).isoformat(),
            'defender': {**{k: True for k in ('AntivirusEnabled', 'RealTimeProtectionEnabled', 'BehaviorMonitorEnabled', 'IsTamperProtected')},
                         'QuickScanEndTime': dt.datetime.now(dt.timezone.utc).isoformat()},
            'firewall': [{'Name': n, 'Enabled': True} for n in ('Domain', 'Private', 'Public')], 'threats': [], 'errors': [], 'startup': [], 'events': [],
            'processes': [{'Name': 'Demo Browser.exe', 'ExecutablePath': 'C:\\Fictional\\browser.exe', 'ProcessId': 101},
                          {'Name': 'Demo Remote Helper.exe', 'ExecutablePath': 'C:\\Fictional\\helper.exe', 'ProcessId': 102}],
            'connections': [{'OwningProcess': 101, 'RemoteAddress': '8.8.8.8', 'RemotePort': 443},
                            {'OwningProcess': 102, 'RemoteAddress': '8.8.4.4', 'RemotePort': 22}],
            'wifiRaw': 'Name : demo-wifi\nState : connected\nSSID : FICTIONAL DEMO NETWORK\nAuthentication : WPA2-Personal\nCipher : CCMP\nSignal : 92%\nBand : 5 GHz',
            'addresses': [], 'neighbors': [],
            'coverageNotes': ['FICTIONAL DEMO: synthetic observations only. No host files, native scan, network probes, or AI service are accessed.']}


def run_demo_review(provider, model, packet, allow_cloud=False, **kwargs):
    connection = packet.get('coverage', {}).get('fictionalEvidenceOnly')
    finding = {'evidence_id': 'E001', 'severity': 'warning', 'reason_code': 'protection_off', 'next_step': 'review_protection'} if connection else {'evidence_id': 'E003', 'severity': 'review', 'reason_code': 'unsigned_remote_access', 'next_step': 'verify_app'}
    return {'provider': provider, 'result': validate_result({'assessment': 'review', 'findings': [finding]}, packet),
            'cloudUsed': False, 'nativeMalwareScanStarted': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--port', type=int, default=8918)
    args = parser.parse_args()
    def runner(script, *arguments, **kwargs):
        if script != 'collect.ps1': raise ValueError('Native actions are disabled in the fictional demo.')
        return snapshot()
    app.run_review = run_demo_review
    app.system_profile = lambda: {'label': 'Windows fictional demo', 'architecture': 'x64', 'assistants': [], 'assistantMode': 'Demo data only; tools and accounts are not inspected.'}
    app.provider_options = lambda: {'providers': [{'id': ident, 'name': label + ' (demo)', 'installed': True, 'supported': True}
                                                 for ident, label in [('ollama', 'Ollama local'), ('codex', 'Codex'), ('claude', 'Claude'), ('gemini', 'Gemini CLI')]],
                                   'localModels': [{'name': 'fictional:model', 'size': 1_400_000_000}], 'note': 'FICTIONAL DEMO: no AI provider is contacted.'}
    with tempfile.TemporaryDirectory(prefix='sentinel-public-demo-') as directory:
        agent = app.Agent(data_dir=Path(directory), backend=WindowsBackend(runner))
        agent.signature_status = lambda paths: {p: 'unsigned' if p.endswith('helper.exe') else 'valid' for p in paths}
        agent.collect()
        agent.state['network'] = {'ssid': 'FICTIONAL DEMO NETWORK', 'subnet': '192.0.2.0/24', 'devices': [
            {'ip': '192.0.2.1', 'kind': 'Fictional router'}, {'ip': '192.0.2.20', 'kind': 'Fictional laptop'}],
            'routerServices': [{'service': 'HTTPS', 'port': 443}], 'completedAt': app.utcnow()}
        agent.launch_job = lambda action: (_ for _ in ()).throw(ValueError('Actions are disabled in the fictional demo.'))
        server = app.Server(('127.0.0.1', args.port), agent)
        threading.Thread(target=agent.monitor, daemon=True, name='fictional-demo-monitor').start()
        timer = threading.Timer(900, server.shutdown); timer.daemon = True; timer.start()
        print(json.dumps({'fictionalDemo': True, 'url': server.origin + '/#token=' + server.token}), flush=True)
        try: server.serve_forever()
        finally:
            timer.cancel(); agent.stop.set(); agent.wakeup.set(); server.server_close()


if __name__ == '__main__': main()
