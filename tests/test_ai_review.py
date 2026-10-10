"""Security boundaries for direct inference; all host observations are fictional."""
import copy
import datetime as dt
import http.client
import json
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from ai_evidence import build_evidence, output_schema, review_prompt, validate_result
import ai_providers as providers
from app import Agent, Server
from backends import WindowsBackend
from engine import BehaviorModel
from privacy import public_report


def snapshot():
    return {'platform': 'Windows', 'collectedAt': dt.datetime.now(dt.timezone.utc).isoformat(),
            'defender': {k: True for k in ('AntivirusEnabled', 'RealTimeProtectionEnabled', 'BehaviorMonitorEnabled')},
            'firewall': [{'Name': name, 'Enabled': True} for name in ('Domain', 'Private', 'Public')], 'errors': [], 'threats': [{'IsActive': False}],
            'wifiRaw': 'State : connected\nSSID : PRIVATE-WIFI-CANARY\nAuthentication : WPA2-Personal\nCipher : CCMP',
            'processes': [{'Name': 'PRIVATE-APP-CANARY.exe', 'ProcessId': 7,
                           'ExecutablePath': 'C:\\Fictional\\PRIVATE-PATH-CANARY.exe', 'CommandLine': 'PRIVATE-COMMAND-CANARY'}],
            'connections': [{'OwningProcess': 7, 'RemoteAddress': '8.8.8.8', 'RemotePort': 22}], 'startup': []}


def evidence():
    return build_evidence({'snapshot': snapshot()}, BehaviorModel(), lambda paths: {p: 'unsigned' for p in paths})


def finding(ident='E003', reason='unsigned_remote_access'):
    return {'assessment': 'review', 'findings': [{'evidence_id': ident, 'severity': 'review',
                                               'reason_code': reason, 'next_step': 'verify_app'}]}


class EvidenceTests(unittest.TestCase):
    def test_identifiers_are_local_only(self):
        packet, aliases = evidence()
        encoded = review_prompt(packet)
        for secret in ('PRIVATE-', '8.8.8.8', 'Fictional', 'ProcessId', 'collectedAt'):
            self.assertNotIn(secret, encoded)
        self.assertIn('PRIVATE-APP-CANARY.exe', json.dumps(aliases))
        self.assertFalse(packet['coverage']['allFilesScanned'])

    def test_download_contents_are_not_signed_or_read(self):
        s = snapshot(); s['processes'][0]['ExecutablePath'] = 'C:\\Fictional\\Downloads\\sample.exe'
        calls = []
        packet, _ = build_evidence({'snapshot': s}, BehaviorModel(), lambda paths: calls.extend(paths) or {})
        self.assertEqual(calls, [])
        self.assertTrue(packet['evidence'][2]['indicators']['temporary_network_process'])

    def test_inactive_history_is_not_an_active_indicator(self):
        packet, _ = evidence()
        self.assertFalse(packet['evidence'][0]['indicators']['native_active_detection'])
        s = snapshot(); s['threats'][0]['IsActive'] = True
        packet, _ = build_evidence({'snapshot': s}, BehaviorModel())
        self.assertTrue(packet['evidence'][0]['indicators']['native_active_detection'])

    def test_stale_future_and_failed_status_are_rejected(self):
        for offset in (-300, 300):
            s = snapshot(); s['collectedAt'] = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=offset)).isoformat()
            with self.assertRaises(ValueError): build_evidence({'snapshot': s}, BehaviorModel())
        with self.assertRaises(ValueError): build_evidence({'snapshot': snapshot(), 'lastError': 'failed'}, BehaviorModel())

    def test_valid_signature_is_not_unsigned_remote_access(self):
        packet, _ = build_evidence({'snapshot': snapshot()}, BehaviorModel(), lambda paths: {p: 'valid' for p in paths})
        self.assertFalse(packet['evidence'][2]['indicators']['unsigned_remote_access'])

    def test_bounded_candidates_disclose_omissions(self):
        s = snapshot(); s['processes'] = []; s['connections'] = []
        for index in range(40):
            s['processes'].append({'Name': f'sample{index}.exe', 'ExecutablePath': f'C:\\Fictional\\sample{index}.exe', 'ProcessId': index})
            s['connections'].append({'OwningProcess': index, 'RemoteAddress': '8.8.8.8', 'RemotePort': 22})
        calls = []
        packet, _ = build_evidence({'snapshot': s}, BehaviorModel(), lambda paths: calls.extend(paths) or {})
        self.assertEqual(len(packet['evidence']), 24)
        self.assertEqual(packet['coverage']['omittedCandidates'], 18)
        self.assertEqual(len(calls), 12)

    def test_startup_command_is_boolean_only(self):
        s = snapshot(); s['startup'] = [{'Command': 'powershell -enc PRIVATE-STARTUP-CANARY'}]
        packet, _ = build_evidence({'snapshot': s}, BehaviorModel())
        self.assertNotIn('PRIVATE-STARTUP-CANARY', json.dumps(packet))
        self.assertTrue(packet['evidence'][-1]['indicators']['persistence_indicator'])

    def test_missing_visibility_and_weak_wifi_are_explicit(self):
        s = snapshot(); s.update(processes=None, firewall=[], wifiRaw='State : connected\nAuthentication : Open\nCipher : None')
        packet, _ = build_evidence({'snapshot': s}, BehaviorModel())
        self.assertTrue(packet['evidence'][0]['indicators']['unknown_visibility'])
        self.assertTrue(packet['evidence'][1]['indicators']['weak_wifi'])


class ResultTests(unittest.TestCase):
    def test_supported_finding_is_accepted_and_duplicates_removed(self):
        packet, _ = evidence(); value = finding(); value['findings'] *= 2
        checked = validate_result(value, packet)
        self.assertEqual(len(checked['findings']), 1)
        self.assertIn('No malware verdict', checked['scope'])

    def test_invented_refs_false_indicators_commands_and_verdicts_rejected(self):
        packet, _ = evidence()
        bad = [finding('E999'), finding(reason='encoded_command'), finding(reason='malware')]
        bad.append(dict(finding(), command='delete something'))
        bad.append({'assessment': 'clean', 'findings': []})
        value = finding(); value['assessment'] = 'no_additional_signals'; bad.append(value)
        bad.append({'assessment': 'review', 'findings': []})
        value = finding(); value['findings'] *= 7; bad.append(value)
        for value in bad:
            with self.subTest(value=value), self.assertRaises(ValueError): validate_result(value, packet)

    def test_schema_binds_reasons_to_actual_evidence(self):
        packet, _ = evidence()
        choices = output_schema(packet)['properties']['findings']['items']['anyOf']
        for item in choices:
            ident = item['properties']['evidence_id']['enum'][0]
            reason = item['properties']['reason_code']['enum'][0]
            flags = next(e['indicators'] for e in packet['evidence'] if e['id'] == ident)
            self.assertIs(flags[reason], True)


class ProviderTests(unittest.TestCase):
    def request(self, endpoint, payload=None, timeout=4):
        if endpoint == 'tags': return {'models': [{'name': 'fictional:local', 'size': 200_000_000}]}
        if endpoint == 'show': return {'model_info': {'test': True}, 'details': {'family': 'fictional'}}
        if endpoint == 'chat':
            self.assertFalse(payload['stream']); self.assertFalse(payload['think'])
            self.assertEqual(payload['keep_alive'], 0)
            self.assertEqual(payload['options']['num_thread'], 2)
            self.assertNotIn('PRIVATE-', payload['messages'][0]['content'])
            return {'done': True, 'message': {'content': json.dumps(finding())}}
        raise AssertionError('Unknown endpoint')

    def test_auto_runs_local_only_without_spawning_a_cli(self):
        with patch.object(providers, 'local_request', side_effect=self.request), patch.object(providers.subprocess, 'run', side_effect=AssertionError('No CLI allowed')):
            result = providers.run_review('auto', '', evidence()[0])
        self.assertFalse(result['cloudUsed']); self.assertFalse(result['nativeMalwareScanStarted'])

    def test_cloud_consent_is_required_before_discovery_or_execution(self):
        with patch.object(providers, 'resolve_cli', side_effect=AssertionError('Do not resolve')):
            for provider in ('codex', 'claude', 'gemini'):
                with self.assertRaises(ValueError): providers.run_review(provider, '', evidence()[0])

    def test_uninstalled_models_never_start_downloads(self):
        with patch.object(providers, 'local_request', side_effect=self.request) as request:
            with self.assertRaises(ValueError): providers.run_review('ollama', 'fictional:missing', evidence()[0])
        self.assertEqual([c.args[0] for c in request.call_args_list], ['tags'])

    def test_cloud_alias_and_tool_call_are_rejected(self):
        for failure in ('remote', 'tools', 'invalid'):
            def request(endpoint, payload=None, timeout=4):
                value = self.request(endpoint, payload, timeout)
                if endpoint == 'show' and failure == 'remote': value['remote_host'] = 'https://example.invalid'
                if endpoint == 'chat' and failure == 'tools': value['message']['tool_calls'] = [{'name': 'shell'}]
                if endpoint == 'chat' and failure == 'invalid': value['message']['content'] = json.dumps(finding('E999'))
                return value
            with patch.object(providers, 'local_request', side_effect=request), self.assertRaises(ValueError):
                providers.run_review('ollama', '', evidence()[0])

    def test_failed_local_inference_has_no_cloud_fallback(self):
        with patch.object(providers, 'local_request', side_effect=OSError('offline')), patch.object(providers, 'resolve_cli', side_effect=AssertionError('No fallback')):
            with self.assertRaises(OSError): providers.run_review('auto', '', evidence()[0])

    def test_cli_flags_disable_tools_hooks_and_mcp(self):
        with patch.object(providers, 'native_command', side_effect=lambda args: args):
            codex = providers.command('codex', 'codex', Path('/fictional'))
            claude = providers.command('claude', 'claude', Path('/fictional'))
        self.assertIn('--ignore-user-config', codex); self.assertIn('read-only', codex)
        for feature in ('shell_tool', 'unified_exec', 'multi_agent', 'apps', 'hooks'): self.assertIn(feature, codex)
        self.assertEqual(claude[claude.index('--tools') + 1], '')
        self.assertIn('--strict-mcp-config', claude); self.assertIn('--safe-mode', claude)
        self.assertNotIn('--dangerously-skip-permissions', claude)
        with patch.object(providers, 'native_command', side_effect=lambda args: args):
            gemini = providers.command('gemini', 'gemini', Path('/fictional'))
        self.assertIn('--admin-policy', gemini); self.assertIn('plan', gemini); self.assertNotIn('--yolo', gemini)
        self.assertIn('none', gemini)

    def test_child_environment_drops_secrets_and_endpoint_overrides(self):
        with patch.dict(providers.os.environ, {'OPENAI_API_KEY': 'PRIVATE-KEY-CANARY', 'ANTHROPIC_API_KEY': 'PRIVATE-KEY-CANARY',
                                              'OLLAMA_HOST': 'https://example.invalid', 'PROJECT_SECRET': 'PRIVATE-KEY-CANARY'}):
            env = providers.provider_environment()
        self.assertNotIn('PRIVATE-KEY-CANARY', json.dumps(env)); self.assertNotIn('OLLAMA_HOST', env)

    def test_cloud_contract_uses_anonymous_stdin_and_clean_working_directory(self):
        packet, _ = evidence()
        for provider in ('codex', 'claude'):
            def execute(args, **kwargs):
                self.assertIs(kwargs['shell'], False)
                self.assertNotIn('PRIVATE-', kwargs['input'])
                self.assertEqual({p.name for p in kwargs['cwd'].iterdir()}, {'schema.json'})
                self.assertEqual(kwargs['timeout'], 180)
                if provider == 'codex':
                    (kwargs['cwd'] / 'result.json').write_text(json.dumps(finding()), encoding='utf-8')
                    return SimpleNamespace(returncode=0, stdout='', stderr='')
                return SimpleNamespace(returncode=0, stdout=json.dumps({'structured_output': finding()}), stderr='')
            with patch.object(providers, 'resolve_cli', return_value=provider), patch.object(providers, 'native_command', side_effect=lambda args: args), patch.object(providers.subprocess, 'run', side_effect=execute):
                result = providers.run_review(provider, '', packet, allow_cloud=True)
            self.assertTrue(result['cloudUsed'])

    def test_cli_failure_never_retries_with_weaker_flags_or_another_provider(self):
        with patch.object(providers, 'resolve_cli', return_value='claude'), patch.object(providers, 'native_command', side_effect=lambda args: args), patch.object(providers.subprocess, 'run', return_value=SimpleNamespace(returncode=1, stdout='', stderr='PRIVATE-ERROR-CANARY')) as execute:
            with self.assertRaisesRegex(ValueError, 'no other provider'): providers.run_review('claude', '', evidence()[0], allow_cloud=True)
        self.assertEqual(execute.call_count, 1)

    def test_loopback_request_forbids_redirects_unknown_endpoints_and_proxies(self):
        with self.assertRaises(ValueError): providers.NoRedirect().redirect_request(None)
        with self.assertRaises(ValueError): providers.local_request('pull')
        class Response:
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def read(self, n): return b'{}'
        class Opener:
            def open(self, request, timeout):
                self_url = request.full_url
                if self_url != 'http://127.0.0.1:11434/api/tags': raise AssertionError(self_url)
                return Response()
        with patch.object(providers, 'build_opener', return_value=Opener()) as opener:
            providers.local_request('tags')
        self.assertEqual(opener.call_args.args[0].proxies, {})


class AgentReviewTests(unittest.TestCase):
    def make_agent(self, directory):
        agent = Agent(data_dir=Path(directory), backend=WindowsBackend(lambda *a, **k: snapshot()))
        agent.state['snapshot'] = snapshot()
        agent.signature_status = lambda paths: {p: 'unsigned' for p in paths}
        return agent

    def test_cloud_preview_is_provider_bound_expiring_and_single_use(self):
        with tempfile.TemporaryDirectory() as directory:
            agent = self.make_agent(directory)
            with self.assertRaises(ValueError): agent.launch_ai_review('codex', allow_cloud=True)
            preview = agent.preview_ai_review('codex')
            with self.assertRaises(ValueError): agent.launch_ai_review('claude', allow_cloud=True, preview_token=preview['previewToken'])
            agent.ai_preview['created'] -= 241
            with self.assertRaises(ValueError): agent.launch_ai_review('codex', allow_cloud=True, preview_token=preview['previewToken'])
            preview = agent.preview_ai_review('codex')
            result = {'result': validate_result(finding(), preview['evidence'])}
            with patch('app.run_review', return_value=result) as review:
                agent.launch_ai_review('codex', allow_cloud=True, preview_token=preview['previewToken'])
                deadline = time.monotonic() + 5
                while agent.state['aiReviews'][-1]['status'] == 'running' and time.monotonic() < deadline: time.sleep(.01)
                self.assertEqual(agent.state['aiReviews'][-1]['status'], 'completed')
                self.assertEqual(review.call_args.args[2], preview['evidence'])
                with self.assertRaises(ValueError): agent.launch_ai_review('codex', allow_cloud=True, preview_token=preview['previewToken'])
            self.assertNotIn('PRIVATE-', json.dumps(public_report(agent.state, agent.model)))
            self.assertEqual(agent.view()['guide']['status'], 'review')
            self.assertTrue(any(f['source'] == 'AI advisory review' for f in agent.view()['findings']))
            agent.state['aiReviews'][-1]['finishedAt'] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=300)).isoformat()
            self.assertFalse(any(f['source'] == 'AI advisory review' for f in agent.view()['findings']))

    def test_running_review_cannot_be_duplicated(self):
        with tempfile.TemporaryDirectory() as directory:
            agent = self.make_agent(directory); agent.state['aiReviews'] = [{'status': 'running'}]
            with self.assertRaises(ValueError): agent.launch_ai_review()

    def test_second_monitor_cannot_bind_the_same_live_port(self):
        with tempfile.TemporaryDirectory() as directory:
            agent = self.make_agent(directory); server = Server(('127.0.0.1', 0), agent)
            try:
                with self.assertRaises(OSError): Server(('127.0.0.1', server.server_port), agent)
            finally:
                server.server_close()

    def test_ai_api_requires_auth_and_mutation_origin(self):
        with tempfile.TemporaryDirectory() as directory:
            agent = self.make_agent(directory); server = Server(('127.0.0.1', 0), agent)
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            try:
                for token, expected in (('', 401), (server.token, 200)):
                    connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
                    with patch('app.provider_options', return_value={'providers': []}):
                        connection.request('GET', '/api/ai/options', headers={'X-Sentinel-Token': token})
                        response = connection.getresponse(); response.read(); self.assertEqual(response.status, expected)
                    connection.close()
                connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
                connection.request('POST', '/api/ai/preview', body='{"provider":"codex"}', headers={'X-Sentinel-Token': server.token, 'Origin': 'https://example.invalid', 'Content-Type': 'application/json'})
                response = connection.getresponse(); response.read(); self.assertEqual(response.status, 403); connection.close()
            finally:
                server.shutdown(); server.server_close(); thread.join(timeout=2)
