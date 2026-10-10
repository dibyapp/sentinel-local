import copy
import datetime as dt
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from app import Agent, Server, run_requested_scan
from backends import WindowsBackend
from engine import BehaviorModel
from guidance import assistant_handoff, next_steps, system_profile
from privacy import public_report


def healthy():
    return {'platform': 'Windows', 'collectedAt': dt.datetime.now(dt.timezone.utc).isoformat(),
            'defender': {k: True for k in ('AntivirusEnabled', 'RealTimeProtectionEnabled', 'BehaviorMonitorEnabled')},
            'firewall': [{'Name': n, 'Enabled': True} for n in ('Domain', 'Private', 'Public')],
            'processes': [], 'connections': [], 'errors': [], 'events': [],
            'threats': [{'ThreatName': 'FICTIONAL-PRIVATE-DETECTION', 'IsActive': False}]}


class GuidanceTests(unittest.TestCase):
    def test_historical_detection_is_not_current_issue(self):
        guide = next_steps({'snapshot': healthy(), 'findings': []}, {'platform': 'Windows', 'actions': ['quick']})
        self.assertEqual(guide['status'], 'clear')
        self.assertEqual(guide['activeThreatCount'], 0)
        self.assertEqual(guide['historicalThreatCount'], 1)

    def test_unreadable_or_missing_firewall_is_unknown(self):
        for field, value in (('errors', ['unavailable']), ('firewall', [])):
            s = healthy(); s[field] = value
            self.assertEqual(next_steps({'snapshot': s}, {'platform': 'Windows'})['status'], 'unknown')

    def test_stale_or_future_snapshot_cannot_claim_clear(self):
        for offset in (-300, 300):
            s = healthy(); s['collectedAt'] = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=offset)).isoformat()
            self.assertEqual(next_steps({'snapshot': s}, {'platform': 'Windows'})['status'], 'unknown')

    def test_active_detection_is_attention(self):
        s = healthy(); s['threats'][0]['IsActive'] = True
        self.assertEqual(next_steps({'snapshot': s}, {'platform': 'Windows'})['status'], 'attention')

    def test_posix_does_not_claim_malware_blocking_or_verified_clean(self):
        s = healthy(); s['platform'] = 'Linux'; s['defender'] = None
        guide = next_steps({'snapshot': s}, {'platform': 'Linux', 'actions': []})
        self.assertEqual(guide['status'], 'limited')
        self.assertIsNone(guide['steps'][1]['action'])

    def test_profile_detects_cli_without_running_it_or_returning_paths(self):
        for system, machine, expected in (('Windows', 'AMD64', 'x64'), ('Darwin', 'arm64', 'ARM64'), ('Linux', 'aarch64', 'ARM64')):
            with patch('guidance.platform.system', return_value=system), patch('guidance.platform.machine', return_value=machine), patch('guidance.shutil.which', side_effect=lambda n: '/fictional/private/bin/' + n if n == 'codex' else None):
                profile = system_profile()
            self.assertEqual(profile['architecture'], expected)
            self.assertTrue(profile['assistants'][0]['cliDetected'])
            self.assertFalse(profile['assistants'][1]['cliDetected'])
            self.assertNotIn('/fictional/private', json.dumps(profile))

    def test_ai_handoff_excludes_all_raw_evidence_and_is_disconnected(self):
        s = healthy()
        s.update(processes=[{'Name': 'PRIVATE-PROCESS-CANARY', 'CommandLine': 'PRIVATE-COMMAND-CANARY', 'ExecutablePath': '/fictional/private-path-canary'}],
                 wifiRaw='SSID : PRIVATE-WIFI-CANARY', errors=['PRIVATE-ERROR-CANARY'],
                 neighbors=[{'IPAddress': '192.0.2.88'}], collectedAt='PRIVATE-TIME-CANARY')
        state = {'snapshot': s, 'findings': [{'severity': 'warning', 'detail': 'PRIVATE-FINDING-CANARY'}],
                 'jobs': [{'result': 'PRIVATE-JOB-CANARY'}], 'token': 'PRIVATE-TOKEN-CANARY'}
        handoff = assistant_handoff(state, BehaviorModel())
        encoded = json.dumps(handoff)
        for marker in ('PRIVATE-', '/fictional/private', '192.0.2.88', 'FICTIONAL-PRIVATE-DETECTION'):
            self.assertNotIn(marker, encoded)
        self.assertFalse(handoff['connected'])
        self.assertEqual(handoff['summary']['threatStatus']['historicalInactive'], 1)

    def test_threat_flags_are_strict_booleans_not_names_or_truthy_strings(self):
        s = healthy(); s['threats'] = [{'IsActive': True}, {'IsActive': False}, {'IsActive': 'false'}, {}]
        report = public_report({'snapshot': s}, BehaviorModel())
        self.assertEqual(report['threatStatus'], {'active': 1, 'historicalInactive': 1, 'unknown': 2})
        s['threats'] = {'IsActive': False}
        self.assertEqual(public_report({'snapshot': s}, BehaviorModel())['threatStatus']['historicalInactive'], 1)

    def test_assistant_api_requires_auth_and_redacts_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            agent = Agent(data_dir=Path(directory), backend=WindowsBackend(lambda *a, **k: healthy()))
            agent.collect()
            server = Server(('127.0.0.1', 0), agent)
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            try:
                for token, expected in (('', 401), (server.token, 200)):
                    connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
                    connection.request('GET', '/api/assistant', headers={'X-Sentinel-Token': token})
                    response = connection.getresponse(); body = response.read().decode(); connection.close()
                    self.assertEqual(response.status, expected)
                    self.assertNotIn('FICTIONAL-PRIVATE-DETECTION', body)
            finally:
                server.shutdown(); server.server_close(); thread.join(timeout=2)


class ScanCommandTests(unittest.TestCase):
    def exercise(self, backend, selection):
        with tempfile.TemporaryDirectory() as directory:
            agent = Agent(data_dir=Path(directory), backend=backend)
            return run_requested_scan(agent, selection)

    def test_unavailable_scan_does_not_invoke_action(self):
        class Fake:
            def collect(self): return healthy()
            def capabilities(self): return {'platform': 'Linux', 'actions': []}
            def action(self, action): raise AssertionError('Must not run')
        self.assertEqual(self.exercise(Fake(), 'quick')['status'], 'unavailable')

    def test_cancelled_or_unmatched_defender_scan_cannot_be_completed(self):
        backend = WindowsBackend(lambda *a, **k: healthy() if a[0] == 'collect.ps1' else {})
        self.assertEqual(self.exercise(backend, 'quick')['status'], 'unverified')

    def test_clamav_detection_is_reported_without_raw_paths(self):
        class Fake:
            def collect(self):
                s = healthy(); s.update(platform='Linux', defender=None, capabilities={'scannerInstalled': True}); return s
            def capabilities(self): return {'platform': 'Linux', 'actions': ['scan']}
            def action(self, action): return {'engine': 'ClamAV', 'exitCode': 1, 'stdout': 'PRIVATE-SCANNER-CANARY'}
        result = self.exercise(Fake(), 'selected')
        self.assertEqual(result['status'], 'completed')
        self.assertTrue(result['detectionsReported'])
        self.assertNotIn('PRIVATE-SCANNER-CANARY', json.dumps(result))

    def test_failed_scan_error_stays_private(self):
        class Fake:
            def collect(self): return healthy()
            def capabilities(self): return {'platform': 'Linux', 'actions': ['scan']}
            def action(self, action): raise RuntimeError('PRIVATE-FAILURE-CANARY')
        result = self.exercise(Fake(), 'selected')
        self.assertEqual(result['status'], 'failed')
        self.assertNotIn('PRIVATE-FAILURE-CANARY', json.dumps(result))
