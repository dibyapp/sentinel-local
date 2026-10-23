"""Fictional product-control regressions: no host collection or provider requests."""
import copy
import datetime as dt
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from app import Agent, Server
from engine import BehaviorModel, assess
from privacy import public_report
from workbench import Workbench, address_scope, connection_delta, finding_key, fingerprint, freshness, markdown_report, socket_keys

NOW = dt.datetime(2026, 10, 1, 12, tzinfo=dt.timezone.utc)


def snapshot(now=NOW):
    return {'platform': 'Windows', 'collectedAt': now.isoformat(),
            'processes': [{'ProcessId': 7, 'Name': 'Fictional browser', 'ExecutablePath': 'Fictional-only-canary'}],
            'connections': [{'OwningProcess': 7, 'LocalAddress': '192.0.2.20', 'LocalPort': 5000, 'RemoteAddress': '8.8.8.8', 'RemotePort': 443}],
            'listeners': [{'OwningProcess': 7, 'LocalAddress': '::', 'LocalPort': 9000}, {'OwningProcess': 7, 'LocalAddress': '127.0.0.1', 'LocalPort': 9001}],
            'startup': [], 'threats': [], 'errors': [], 'neighbors': [], 'addresses': [],
            'defender': {'AntivirusEnabled': True, 'RealTimeProtectionEnabled': True},
            'firewall': [{'Name': name, 'Enabled': True} for name in ('Domain', 'Private', 'Public')]}


class Backend:
    name = 'Windows'
    def capabilities(self):
        return {'platform': 'Windows', 'actions': [], 'engine': 'Fictional engine'}
    def collect(self):
        return snapshot(dt.datetime.now(dt.timezone.utc))


class DerivedViewsTests(unittest.TestCase):
    def test_address_scope_ipv4_ipv6_mapped_and_invalid(self):
        cases = {'::1': 'loopback', '127.0.0.1': 'loopback', '::ffff:127.0.0.1': 'loopback',
                 '::': 'all-interfaces', '0.0.0.0': 'all-interfaces', '8.8.8.8': 'public',
                 '2606:4700:4700::1111': 'public', 'fe80::1%eth0': 'local-or-reserved',
                 '192.0.2.20': 'local-or-reserved', '100.64.0.1': 'local-or-reserved', 'not-an-IP': 'unknown'}
        for value, expected in cases.items():
            with self.subTest(value=value): self.assertEqual(address_scope(value), expected)

    def test_freshness_rejects_missing_naive_future_and_stale(self):
        for value in (None, 'bad', '2026-10-01T12:00:00', (NOW + dt.timedelta(minutes=2)).isoformat()):
            self.assertEqual(freshness(value, NOW)['status'], 'unknown')
        self.assertEqual(freshness((NOW - dt.timedelta(seconds=241)).isoformat(), NOW)['status'], 'stale')
        self.assertEqual(freshness(NOW.isoformat(), NOW)['status'], 'fresh')

    def test_delta_handles_missing_first_sample_and_socket_churn(self):
        w = Workbench(); s = snapshot()
        w.observe(s, 10, now=NOW); self.assertEqual(w.delta['status'], 'unavailable')
        changed = copy.deepcopy(s); changed['connections'][0]['LocalPort'] += 1
        w.observe(changed, 20, now=NOW)
        self.assertEqual(w.delta, {'status': 'observed', 'opened': 1, 'closed': 1, 'persisting': 0})
        self.assertIsNone(socket_keys({'connections': None}))
        self.assertEqual(connection_delta(set(), set())['opened'], 0)

    def test_failed_and_missing_samples_break_connection_comparison(self):
        w = Workbench(); w.observe(snapshot(), 1, now=NOW)
        w.observe(None, 3, success=False, now=NOW); w.observe(snapshot(), 1, now=NOW)
        self.assertEqual(w.delta['status'], 'unavailable')
        s = snapshot(); s['connections'] = None; w.observe(s, 1, now=NOW)
        self.assertEqual(w.delta['status'], 'unavailable')

    def test_collections_are_bounded_and_errors_are_not_clean_samples(self):
        w = Workbench()
        for _ in range(130): w.observe(snapshot(), 12, now=NOW)
        w.observe(None, 30, success=False, now=NOW)
        view = w.view(snapshot(), [], NOW, last_error=True)
        self.assertEqual(len(w.collections), 120)
        self.assertEqual(view['collectionHealth']['failures'], 1)
        self.assertEqual(view['freshness']['status'], 'unverified')

    def test_protection_changes_include_loss_of_visibility_not_initial_baseline(self):
        w = Workbench(); s = snapshot(); w.observe(s, 1, now=NOW)
        self.assertEqual(w.changes, [])
        s['defender']['RealTimeProtectionEnabled'] = False; w.observe(s, 2, now=NOW)
        s['defender'] = None; w.observe(s, 3, now=NOW)
        self.assertTrue(any(c['before'] is True and c['after'] is False for c in w.changes))
        self.assertTrue(any(c['after'] is None for c in w.changes))

    def test_incomplete_firewall_profiles_do_not_claim_all_on(self):
        w = Workbench(); s = snapshot(); w.observe(s, 1, now=NOW)
        s['firewall'] = s['firewall'][:1]; w.observe(s, 1, now=NOW)
        self.assertEqual(w.last_flags['firewall'], None)
        firewall = next(sensor for sensor in w.view(s, [], NOW)['sensors'] if sensor['name'] == 'firewall')
        self.assertEqual(firewall['status'], 'partial')
        s['firewall'] = None
        self.assertEqual(next(sensor for sensor in w.view(s, [], NOW)['sensors'] if sensor['name'] == 'firewall')['status'], 'unavailable')

    def test_listeners_distinguish_all_interfaces_loopback_and_unavailable(self):
        w = Workbench(); result = w.view(snapshot(), [], NOW)
        self.assertEqual([x['review'] for x in result['listeners']], [True, False])
        self.assertEqual(result['listeners'][0]['application'], 'Fictional browser')
        s = snapshot(); s['listeners'] = None
        self.assertFalse(w.view(s, [], NOW)['listenersAvailable'])

    def test_review_and_snooze_expire_and_changed_evidence_reopens(self):
        w = Workbench(); finding = {'id': 'sample', 'detail': 'first', 'source': 'Local behavior model', 'severity': 'review'}
        w.mark(finding, 'snoozed', NOW)
        self.assertEqual(w.view(snapshot(), [finding], NOW)['findingStates'][finding_key(finding)]['status'], 'snoozed')
        self.assertEqual(w.view(snapshot(), [finding], NOW + dt.timedelta(hours=1))['findingStates'][finding_key(finding)]['status'], 'open')
        w.mark(finding, 'reviewed', NOW)
        changed = {**finding, 'detail': 'different evidence'}
        self.assertEqual(w.view(snapshot(), [changed], NOW)['findingStates'][finding_key(changed)]['status'], 'open')
        self.assertEqual(w.view(snapshot(), [finding], NOW + dt.timedelta(days=7))['findingStates'][finding_key(finding)]['status'], 'open')

    def test_critical_findings_cannot_be_reviewed_or_snoozed(self):
        w = Workbench(); f = {'id': 'native', 'severity': 'critical'}
        for status in ('reviewed', 'snoozed'):
            with self.assertRaises(ValueError): w.mark(f, status, NOW)
        w.mark(f, 'open', NOW)
        self.assertFalse(w.marks)

    def test_persistence_drops_untrusted_fields_and_bounds_data(self):
        stored = {'settings': {'learningPaused': 'yes', 'retentionDays': True}, 'marks': {'untrusted': {'status': 'snoozed'}},
                  'changes': [{'at': NOW.isoformat(), 'field': 'untrusted', 'before': False, 'after': True}],
                  'collections': [{'at': NOW.isoformat(), 'durationMs': float('inf'), 'errors': 0, 'success': True}],
                  'reminder': {'days': True, 'dueAt': NOW.isoformat()}}
        w = Workbench(stored)
        self.assertEqual(w.settings, {'learningPaused': False, 'retentionDays': 30})
        self.assertEqual(w.reminder['days'], 0); self.assertFalse(w.marks); self.assertFalse(w.collections)
        self.assertNotIn('untrusted', json.dumps(w.persisted()))

    def test_retention_removes_old_records_but_preserves_recent(self):
        w = Workbench(); w.observe(snapshot(), 1, now=NOW - dt.timedelta(days=8))
        w.observe(snapshot(), 1, now=NOW)
        w.settings['retentionDays'] = 7; w.prune(NOW)
        self.assertEqual(len(w.collections), 1)

    def test_markdown_report_does_not_render_private_or_injected_fields(self):
        state = {'snapshot': snapshot(), 'findings': [{'severity': 'warning', 'detail': 'PRIVATE-DETAIL'}]}
        report = public_report(state, BehaviorModel()); report['platform'] = '<script>PRIVATE</script>'
        report['counts']['connections'] = 'PRIVATE-COUNT'; report['protection']['AntivirusEnabled'] = 'PRIVATE-FLAG'
        report['collection']['freshness'] = 'PRIVATE-STATUS'
        text = markdown_report(report)
        for value in ('PRIVATE', 'Fictional-only-canary', '8.8.8.8', '192.0.2.20', NOW.isoformat()):
            self.assertNotIn(value, text)
        self.assertIn('unknown', text); self.assertIn('does not certify', text)

    def test_pause_evaluates_model_without_learning_or_gateway_mutation(self):
        model = BehaviorModel(); s = snapshot()
        s['processes'][0].update(Name='powershell.exe', CommandLine='powershell -enc ZmljdGlvbmFs')
        before = copy.deepcopy(model.state)
        self.assertTrue(assess(s, model, learn=False))
        self.assertEqual(model.state, before)


class AgentControlsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.agent = Agent(data_dir=self.root, backend=Backend())
        self.agent.collect()
    def tearDown(self): self.temp.cleanup()

    def test_pause_persists_and_resume_advances_samples(self):
        count = self.agent.model.state['samples']
        self.agent.control({'action': 'learning', 'paused': True}); self.agent.collect()
        self.assertEqual(self.agent.model.state['samples'], count)
        restarted = Agent(data_dir=self.root, backend=Backend())
        self.assertTrue(restarted.workbench.settings['learningPaused'])
        self.agent.control({'action': 'learning', 'paused': False}); self.agent.collect()
        self.assertEqual(self.agent.model.state['samples'], count + 1)

    def test_baseline_reset_is_reversible_and_requires_confirmation(self):
        original = copy.deepcopy(self.agent.model.state)
        with self.assertRaises(ValueError): self.agent.control({'action': 'baseline-reset', 'confirmed': False})
        self.agent.control({'action': 'baseline-reset', 'confirmed': True})
        self.assertEqual(self.agent.model.state['samples'], 0)
        self.assertTrue(self.agent.view()['workbench']['modelBackupAvailable'])
        self.agent.control({'action': 'baseline-restore', 'confirmed': True})
        self.assertEqual(self.agent.model.state, original)

    def test_baseline_changes_refuse_running_ai_and_restore_without_backup(self):
        with self.assertRaises(ValueError): self.agent.control({'action': 'baseline-restore', 'confirmed': True})
        self.agent.state['aiReviews'] = [{'status': 'running'}]
        with self.assertRaises(ValueError): self.agent.control({'action': 'baseline-reset', 'confirmed': True})

    def test_reset_preserves_historical_ai_journal_but_invalidates_current_evidence(self):
        self.agent.state['aiReviews'] = [{'id': 'historical', 'status': 'completed', 'snapshotFingerprint': fingerprint(self.agent.state['snapshot'])}]
        self.agent.control({'action': 'baseline-reset', 'confirmed': True})
        self.assertEqual(self.agent.state['aiReviews'][0]['id'], 'historical')
        self.assertFalse(self.agent.view()['aiReviews'][0]['evidenceCurrent'])

    def test_reminders_never_start_a_scan_or_provider(self):
        with patch.object(self.agent.backend, 'collect') as collect, patch.object(self.agent, 'launch_job') as job:
            self.agent.control({'action': 'reminder', 'days': 7})
            self.agent.workbench.reminder['dueAt'] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)).isoformat()
            self.assertTrue(self.agent.view()['workbench']['reminder']['due'])
            self.agent.control({'action': 'reminder-done'})
            self.assertFalse(self.agent.view()['workbench']['reminder']['due'])
            collect.assert_not_called(); job.assert_not_called()
        self.agent.control({'action': 'reminder', 'days': 0})
        with self.assertRaises(ValueError): self.agent.control({'action': 'reminder-done'})

    def test_invalid_control_types_unknown_fields_and_actions_are_rejected(self):
        for request in ({'action': 'learning', 'paused': 1}, {'action': 'retention', 'days': True},
                        {'action': 'reminder', 'days': -1}, {'action': 'learning', 'paused': True, 'command': 'no'},
                        {'action': 'execute'}, {'action': []}):
            with self.subTest(request=request), self.assertRaises(ValueError): self.agent.control(request)

    def test_stale_review_key_and_critical_override_are_rejected(self):
        with self.assertRaises(ValueError): self.agent.control({'action': 'finding', 'key': '0' * 64, 'status': 'reviewed'})
        self.agent.state['findings'] = [{'id': 'active', 'severity': 'critical', 'detail': 'native engine', 'source': 'Security checks'}]
        key = self.agent.view()['findings'][0]['reviewKey']
        with self.assertRaises(ValueError): self.agent.control({'action': 'finding', 'key': key, 'status': 'snoozed'})

    def test_review_does_not_lower_status_or_report_counts(self):
        self.agent.state['findings'] = [{'id': 'advisory', 'severity': 'review', 'detail': 'fictional', 'source': 'Local behavior model'}]
        before = self.agent.report()['findings']
        key = self.agent.view()['findings'][0]['reviewKey']
        self.agent.control({'action': 'finding', 'key': key, 'status': 'reviewed'})
        self.assertEqual(self.agent.report()['findings'], before)
        self.assertEqual(len(self.agent.view()['findings']), 1)

    def test_retention_preserves_scan_jobs_and_ai_journals(self):
        old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=20)).isoformat()
        self.agent.state['history'].append({'time': old})
        self.agent.state['alertHistory'] = [{'observedAt': old}]
        self.agent.state['jobs'] = [{'id': 'keep', 'status': 'completed'}]
        self.agent.control({'action': 'retention', 'days': 7})
        self.assertFalse(self.agent.state['alertHistory']); self.assertEqual(self.agent.state['jobs'][0]['id'], 'keep')

    def test_ai_result_is_current_only_for_same_fresh_snapshot(self):
        self.agent.state['aiReviews'] = [{'id': 'test', 'status': 'completed', 'snapshotFingerprint': fingerprint(self.agent.state['snapshot'])}]
        self.assertTrue(self.agent.view()['aiReviews'][0]['evidenceCurrent'])
        self.agent.state['snapshot']['processes'][0]['Name'] = 'different'
        self.assertFalse(self.agent.view()['aiReviews'][0]['evidenceCurrent'])

    def test_preview_freezes_exact_snapshot_without_transmitting_fingerprint(self):
        with patch.object(self.agent, 'ai_evidence', return_value=({'coverage': {}}, {})):
            preview = self.agent.preview_ai_review('codex')
        self.assertNotIn('snapshotFingerprint', preview['evidence'])
        self.assertEqual(self.agent.ai_preview['snapshotFingerprint'], fingerprint(self.agent.state['snapshot']))

    def test_api_auth_origin_and_readable_report_privacy(self):
        server = Server(('127.0.0.1', 0), self.agent)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            for token, origin, expected in [('', server.origin, 401), (server.token, 'https://example.invalid', 403), (server.token, server.origin, 200)]:
                connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
                connection.request('POST', '/api/control', json.dumps({'action': 'learning', 'paused': True}),
                    {'X-Sentinel-Token': token, 'Origin': origin, 'Content-Type': 'application/json'})
                response = connection.getresponse(); response.read(); self.assertEqual(response.status, expected); connection.close()
            connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
            connection.request('GET', '/api/report.md', headers={'X-Sentinel-Token': server.token})
            response = connection.getresponse(); text = response.read().decode()
            self.assertEqual(response.status, 200); self.assertIn('text/markdown', response.getheader('Content-Type'))
            self.assertEqual(response.getheader('Cache-Control'), 'no-store')
            self.assertNotIn('Fictional-only-canary', text); self.assertNotIn('8.8.8.8', text)
            connection.close()
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)


if __name__ == '__main__': unittest.main()
