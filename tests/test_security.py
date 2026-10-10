import copy
import datetime as dt
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import app
from backends import WindowsBackend

from app import Agent, Server, wifi_adapter, network_scan
from engine import BehaviorModel, assess, timestamp, scan_events


def snapshot():
    return {'collectedAt': dt.datetime.now(dt.timezone.utc).isoformat(),
            'defender': {'AntivirusEnabled': True, 'RealTimeProtectionEnabled': True, 'BehaviorMonitorEnabled': True},
            'firewall': [{'Name': 'Public', 'Enabled': True}], 'processes': [], 'connections': [],
            'wifiRaw': 'Name : Wi-Fi\nState : connected\nSSID : Test\nAuthentication : WPA2-Personal\nCipher : CCMP',
            'addresses': [{'interface': 'Wi-Fi', 'index': 1, 'addresses': [{'IPAddress': '172.20.30.7', 'PrefixLength': 24}], 'gateways': ['172.20.30.1']}],
            'neighbors': []}


class AssessmentTests(unittest.TestCase):
    def test_disabled_defenses_and_active_threats_reported(self):
        s = snapshot(); s['defender']['RealTimeProtectionEnabled'] = False
        s['firewall'][0]['Enabled'] = False
        s['threats'] = [{'ThreatID': 1, 'ThreatName': 'Test', 'IsActive': True}]
        result = assess(s, BehaviorModel())
        self.assertEqual(len([f for f in result if f['severity'] == 'critical']), 3)

    def test_unknown_defender_is_not_clean(self):
        s = snapshot(); s['defender'] = None
        self.assertIn('defender-unavailable', [f['id'] for f in assess(s, BehaviorModel())])

    def test_historical_detection_is_not_active(self):
        s = snapshot(); s['threats'] = [{'ThreatID': 1, 'IsActive': False}]
        self.assertEqual(assess(s, BehaviorModel()), [])

    def test_wifi_weak_cipher(self):
        s = snapshot(); s['wifiRaw'] = 'Authentication : WPA-Personal\nCipher : TKIP'
        self.assertIn('wifi-encryption', [f['id'] for f in assess(s, BehaviorModel())])

    def test_baseline_learns_then_flags_connection_spike_without_poisoning(self):
        model = BehaviorModel(); s = snapshot()
        s['processes'] = [{'Name': 'browser.exe', 'ExecutablePath': 'C:\\Programs\\browser.exe', 'ProcessId': 1}]
        s['connections'] = [{'OwningProcess': 1, 'RemoteAddress': '8.8.8.8', 'RemotePort': 443}]
        for _ in range(20): self.assertEqual(model.inspect(s), [])
        before = copy.deepcopy(model.state['processes'])
        s['connections'] *= 20
        self.assertTrue(model.inspect(s))
        self.assertEqual(before, model.state['processes'])

    def test_encoded_command_is_advisory(self):
        model = BehaviorModel(); s = snapshot()
        s['processes'] = [{'Name': 'powershell.exe', 'ProcessId': 1, 'CommandLine': 'powershell.exe -EncodedCommand YQ=='}]
        findings = model.inspect(s)
        self.assertEqual(findings[0]['severity'], 'review')
        self.assertEqual(model.state['processes'], {})

    def test_missing_tcp_sensor_does_not_poison_baseline_or_advance_warmup(self):
        model = BehaviorModel(); s = snapshot()
        s['processes'] = [{'Name': 'fictional.exe', 'ProcessId': 1}]
        s['connections'] = None
        self.assertEqual(model.inspect(s), [])
        self.assertEqual(model.state['samples'], 0)
        self.assertEqual(model.state['processes'], {})

    def test_gateway_change_does_not_replace_original_baseline(self):
        s = snapshot(); model = BehaviorModel()
        s['neighbors'] = [{'IPAddress': '172.20.30.1', 'InterfaceIndex': 1, 'LinkLayerAddress': 'AA-BB'}]
        assess(s, model)
        s['neighbors'][0]['LinkLayerAddress'] = 'CC-DD'
        result = assess(s, model)
        self.assertTrue(any(f['id'].startswith('gateway-mac:') for f in result))
        self.assertEqual(list(model.state['gatewayMacs'].values()), ['AA-BB'])

    def test_powershell_date_parses(self):
        self.assertEqual(timestamp('/Date(1000+0530)/').timestamp(), 1)

    def test_scan_terminals_must_match_start_id(self):
        s = snapshot()
        one = '{11111111-1111-1111-1111-111111111111}'
        two = '{22222222-2222-2222-2222-222222222222}'
        s['events'] = [{'Id': 1000, 'TimeCreated': '2026-01-01T00:00:00Z', 'Message': one},
                       {'Id': 1001, 'TimeCreated': '2026-01-01T00:01:00Z', 'Message': two}]
        self.assertEqual(next(x for x in scan_events(s) if x['id'] == one)['status'], 'running')
        s['events'].append({'Id': 1002, 'TimeCreated': '2026-01-01T00:02:00Z', 'Message': one})
        self.assertEqual(next(x for x in scan_events(s) if x['id'] == one)['status'], 'stopped')


class NetworkScopeTests(unittest.TestCase):
    def test_selects_wifi_ignoring_vpn_and_limits_large_network(self):
        s = snapshot(); s['addresses'][0]['addresses'][0] = {'IPAddress': '172.20.30.7', 'PrefixLength': 16}
        s['addresses'].insert(0, {'interface': 'VPN', 'index': 2, 'addresses': [{'IPAddress': '10.250.60.2', 'PrefixLength': 8}]})
        adapter, _, network, gateways = wifi_adapter(s)
        self.assertEqual(adapter['interface'], 'Wi-Fi')
        self.assertEqual(str(network), '172.20.30.0/24')
        self.assertEqual(gateways, ['172.20.30.1'])

    def test_public_wifi_discovery_refused(self):
        s = snapshot(); s['addresses'][0]['addresses'][0]['IPAddress'] = '8.8.8.8'
        with self.assertRaises(ValueError): wifi_adapter(s)

    def test_disconnected_and_stale_refused(self):
        s = snapshot(); s['wifiRaw'] = 'State : disconnected'
        with self.assertRaises(ValueError): wifi_adapter(s)
        s = snapshot(); s['collectedAt'] = '2000-01-01T00:00:00+00:00'
        with self.assertRaises(ValueError): wifi_adapter(s)

    def test_network_inventory_excludes_broadcast_and_zero_mac(self):
        s = snapshot(); s['addresses'][0]['addresses'][0] = {'IPAddress': '172.20.30.2', 'PrefixLength': 29}
        s['neighbors'] = [{'IPAddress': '172.20.30.7', 'InterfaceIndex': 1, 'LinkLayerAddress': 'FF-FF-FF-FF-FF-FF'},
                          {'IPAddress': '172.20.30.3', 'InterfaceIndex': 1, 'LinkLayerAddress': '00-00-00-00-00-00'},
                          {'IPAddress': '172.20.30.4', 'InterfaceIndex': 1, 'LinkLayerAddress': 'AA-BB-CC-DD-EE-FF'}]
        with patch('app.subprocess.run') as runner, patch('app.socket.socket') as socket_mock:
            runner.return_value.returncode = 1
            socket_mock.return_value.__enter__.return_value.connect.side_effect = OSError('closed')
            result = network_scan(s)
        self.assertEqual({x['ip'] for x in result['devices']}, {'172.20.30.1', '172.20.30.2', '172.20.30.4'})


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.agent = Agent(data_dir=Path(self.temp.name), backend=WindowsBackend(lambda *args, **kwargs: app.powershell(*args, **kwargs)))
        self.agent.state['snapshot'] = snapshot()
        self.server = Server(('127.0.0.1', 0), self.agent)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.temp.cleanup()

    def request(self, method='GET', path='/api/status', body=None, **headers):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        if body is not None: body = json.dumps(body)
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse(); payload = response.read(); status = response.status
        connection.close()
        return status, payload

    def test_status_requires_token(self):
        self.assertEqual(self.request()[0], 401)
        self.assertEqual(self.request(**{'X-Sentinel-Token': self.server.token})[0], 200)

    def test_non_ascii_token_is_denied_without_server_error(self):
        self.assertEqual(self.request(**{'X-Sentinel-Token': 'invalid-é'})[0], 401)

    def test_host_rebinding_refused(self):
        self.assertEqual(self.request(Host='evil.example', **{'X-Sentinel-Token': self.server.token})[0], 403)

    def test_cross_origin_mutation_refused_even_with_token(self):
        self.assertEqual(self.request('POST', '/api/action', {'action': 'quick'}, Origin='https://evil.example', **{'X-Sentinel-Token': self.server.token})[0], 403)

    def test_mutation_without_origin_refused(self):
        self.assertEqual(self.request('POST', '/api/action', {'action': 'quick'}, **{'X-Sentinel-Token': self.server.token})[0], 403)

    def test_command_injection_is_never_executed(self):
        with patch('app.powershell') as runner:
            status, _ = self.request('POST', '/api/action', {'action': 'quick; whoami'}, Origin=self.server.origin, **{'X-Sentinel-Token': self.server.token})
            self.assertEqual(status, 400)
            runner.assert_not_called()

    def test_reports_omit_process_command_lines(self):
        self.agent.state['snapshot']['processes'] = [{'Name': 'test.exe', 'CommandLine': 'secret'}]
        report = self.agent.report()
        self.assertNotIn('secret', json.dumps(report))
        self.assertNotIn('snapshot', report)
        self.assertEqual(self.agent.state['snapshot']['processes'][0]['CommandLine'], 'secret')

    def test_clamav_detection_remains_a_visible_historical_finding(self):
        self.agent.state['jobs'] = [{'id': 'fictional-scan', 'status': 'completed', 'result': {'engine': 'ClamAV', 'exitCode': 1, 'output': 'FICTIONAL-PRIVATE-SCAN-OUTPUT'}}]
        findings = self.agent.view()['findings']
        self.assertTrue(any(f['source'] == 'ClamAV' and f['severity'] == 'critical' for f in findings))
        self.assertNotIn('FICTIONAL-PRIVATE-SCAN-OUTPUT', json.dumps(self.agent.report()))

    def test_interrupted_scan_is_not_reported_as_completed(self):
        s = snapshot(); scan_id = '{11111111-1111-1111-1111-111111111111}'
        start = dt.datetime.now(dt.timezone.utc)
        s['events'] = [{'Id': 1000, 'TimeCreated': start.isoformat(), 'Message': scan_id},
                       {'Id': 1002, 'TimeCreated': (start + dt.timedelta(seconds=1)).isoformat(), 'Message': scan_id}]
        with patch('app.powershell', side_effect=[{'action': 'quick'}, s]):
            self.agent.launch_job('quick')
            self.assertTrue(self.agent.wakeup.wait(2))
        self.assertEqual(self.agent.view()['jobs'][-1]['status'], 'unverified')

    def test_completed_scan_requires_matching_completion_event(self):
        s = snapshot(); scan_id = '{11111111-1111-1111-1111-111111111111}'
        start = dt.datetime.now(dt.timezone.utc)
        s['events'] = [{'Id': 1000, 'TimeCreated': start.isoformat(), 'Message': scan_id},
                       {'Id': 1001, 'TimeCreated': (start + dt.timedelta(seconds=1)).isoformat(), 'Message': scan_id}]
        with patch('app.powershell', side_effect=[{'action': 'quick'}, s]):
            self.agent.launch_job('quick')
            self.assertTrue(self.agent.wakeup.wait(2))
        self.assertEqual(self.agent.view()['jobs'][-1]['status'], 'completed')


if __name__ == '__main__':
    unittest.main()

