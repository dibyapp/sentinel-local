"""Local monitoring controls and derived views. No scanners or AI are invoked here."""
import copy
import datetime as dt
import hashlib
import ipaddress
import math

from engine import rows, timestamp

UTC = dt.timezone.utc
FLAGS = ('AntivirusEnabled', 'RealTimeProtectionEnabled', 'BehaviorMonitorEnabled', 'IsTamperProtected')
SOURCES = ('processes', 'connections', 'listeners', 'startup', 'firewall', 'threats')


def parsed(value):
    try:
        moment = timestamp(value)
        return moment.astimezone(UTC) if moment and moment.tzinfo else None
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def freshness(value, now):
    moment = parsed(value)
    age = (now - moment).total_seconds() if moment else None
    return {'status': 'unknown' if age is None or age < -5 else 'stale' if age > 240 else 'fresh',
            'ageSeconds': max(0, int(age)) if age is not None else None}


def fingerprint(snapshot):
    # Bind explanations to the full private observation without exporting it.
    import json
    return hashlib.sha256(json.dumps(snapshot, sort_keys=True, default=str).encode()).hexdigest()


def finding_key(finding):
    import json
    fields = [finding.get(name) for name in ('id', 'source', 'severity', 'detail')]
    return hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest()


def address_scope(value):
    try:
        address = ipaddress.ip_address(str(value).split('%', 1)[0])
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        if address.is_unspecified:
            return 'all-interfaces'
        if address.is_loopback:
            return 'loopback'
        return 'public' if address.is_global else 'local-or-reserved'
    except ValueError:
        return 'unknown'


def socket_keys(snapshot):
    if snapshot.get('connections') is None:
        return None
    return {tuple(str(c.get(k, '')) for k in ('OwningProcess', 'LocalAddress', 'LocalPort', 'RemoteAddress', 'RemotePort'))
            for c in rows(snapshot.get('connections'))}


def connection_delta(previous, current):
    if previous is None or current is None:
        return {'status': 'unavailable', 'opened': None, 'closed': None, 'persisting': None}
    return {'status': 'observed', 'opened': len(current - previous), 'closed': len(previous - current),
            'persisting': len(current & previous)}


class Workbench:
    def __init__(self, stored=None):
        self.settings = {'learningPaused': False, 'retentionDays': 30}
        self.marks = {}
        self.collections = []
        self.changes = []
        self.reminder = {'days': 0, 'dueAt': None}
        self.last_flags = None
        self.last_connections = None
        self.delta = connection_delta(None, None)
        stored = stored if isinstance(stored, dict) else {}
        settings = stored.get('settings', {})
        if isinstance(settings, dict):
            if type(settings.get('learningPaused')) is bool:
                self.settings['learningPaused'] = settings['learningPaused']
            if type(settings.get('retentionDays')) is int and settings['retentionDays'] in (7, 30, 90):
                self.settings['retentionDays'] = settings['retentionDays']
        for key, value in (stored.get('marks', {}) if isinstance(stored.get('marks'), dict) else {}).items():
            if (isinstance(key, str) and len(key) == 64 and all(c in '0123456789abcdef' for c in key)
                    and isinstance(value, dict) and value.get('status') in ('reviewed', 'snoozed') and parsed(value.get('until'))):
                self.marks[key] = {'status': value['status'], 'until': value['until']}
        self.marks = dict(list(self.marks.items())[-500:])
        reminder = stored.get('reminder', {})
        if isinstance(reminder, dict) and type(reminder.get('days')) is int and reminder['days'] in (1, 7, 30) and parsed(reminder.get('dueAt')):
            self.reminder = {'days': reminder['days'], 'dueAt': reminder['dueAt']}
        # Reload only known numeric/enum fields; raw persisted text never becomes UI markup.
        for item in rows(stored.get('collections'))[-120:]:
            if not isinstance(item, dict) or not parsed(item.get('at')):
                continue
            duration = item.get('durationMs')
            errors = item.get('errors')
            if (type(duration) in (int, float) and math.isfinite(duration) and 0 <= duration <= 86_400_000
                    and type(errors) is int and 0 <= errors <= 10000 and type(item.get('success')) is bool):
                self.collections.append({'at': item['at'], 'durationMs': round(duration), 'errors': errors, 'success': item['success']})
        for item in rows(stored.get('changes'))[-100:]:
            if (isinstance(item, dict) and item.get('field') in (*FLAGS, 'firewall') and parsed(item.get('at'))
                    and all(type(item.get(k)) is bool or item.get(k) is None for k in ('before', 'after'))):
                self.changes.append({k: item.get(k) for k in ('at', 'field', 'before', 'after')})

    def persisted(self):
        return copy.deepcopy({'schema': 1, 'settings': self.settings, 'marks': self.marks,
                              'collections': self.collections, 'changes': self.changes, 'reminder': self.reminder})

    def prune(self, now):
        cutoff = now - dt.timedelta(days=self.settings['retentionDays'])
        for name in ('collections', 'changes'):
            setattr(self, name, [item for item in getattr(self, name) if (parsed(item.get('at')) or dt.datetime.min.replace(tzinfo=UTC)) >= cutoff])
        self.marks = {key: value for key, value in self.marks.items() if parsed(value['until']) > now}

    def observe(self, snapshot, duration_ms, success=True, now=None):
        now = now or dt.datetime.now(UTC)
        self.collections.append({'at': now.isoformat(), 'durationMs': max(0, round(duration_ms)),
                                 'errors': len(rows((snapshot or {}).get('errors'))) if success else 1, 'success': success})
        self.collections = self.collections[-120:]
        if success:
            defender = snapshot.get('defender') or {}
            flags = {k: defender.get(k) if type(defender.get(k)) is bool else None for k in FLAGS}
            profiles = snapshot.get('firewall')
            expected = 3 if snapshot.get('platform') == 'Windows' else 1
            known = rows(profiles)
            values = [p.get('Enabled') for p in known]
            flags['firewall'] = (False if any(v is False or v == 0 for v in values) else
                                 True if len(known) >= expected and all(v is True or v == 1 for v in values) else None)
            if self.last_flags is not None:
                for field, value in flags.items():
                    if self.last_flags[field] != value:
                        self.changes.append({'at': now.isoformat(), 'field': field, 'before': self.last_flags[field], 'after': value})
            self.last_flags = flags
            self.changes = self.changes[-100:]
            current = socket_keys(snapshot)
            self.delta = connection_delta(self.last_connections, current)
            self.last_connections = current
        else:
            # Never compare across a failed/missing sample as if activity were continuous.
            self.last_connections = None
            self.delta = connection_delta(None, None)
        self.prune(now)

    def mark(self, finding, status, now):
        if status not in ('reviewed', 'snoozed', 'open'):
            raise ValueError('Choose open, reviewed, or snoozed.')
        key = finding_key(finding)
        if status == 'open':
            self.marks.pop(key, None)
        elif finding.get('severity') == 'critical':
            raise ValueError('Critical findings always remain open. Review the native engine or protection setting.')
        else:
            if len(self.marks) >= 500 and key not in self.marks:
                self.marks.pop(next(iter(self.marks)))
            duration = dt.timedelta(hours=1) if status == 'snoozed' else dt.timedelta(days=7)
            self.marks[key] = {'status': status, 'until': (now + duration).isoformat()}

    def view(self, snapshot, findings, now, last_error=False):
        snapshot = snapshot or {}
        self.prune(now)
        fresh = freshness(snapshot.get('collectedAt'), now)
        if last_error:
            fresh['status'] = 'unverified'
        states = {}
        for finding in findings:
            key = finding_key(finding)
            state = self.marks.get(key, {}) if finding.get('severity') != 'critical' else {}
            states[key] = {'status': state.get('status', 'open'), 'until': state.get('until')}
        sensors = [{'name': name, 'available': snapshot.get(name) is not None,
                    'status': fresh['status'] if snapshot.get(name) is not None else 'unavailable'} for name in SOURCES]
        profiles = rows(snapshot.get('firewall'))
        expected = 3 if snapshot.get('platform') == 'Windows' else 1
        if fresh['status'] == 'fresh' and snapshot.get('firewall') is not None and (
                len(profiles) < expected or any(p.get('Enabled') not in (True, False, 0, 1) for p in profiles)):
            next(sensor for sensor in sensors if sensor['name'] == 'firewall')['status'] = 'partial'
        listeners = []
        by_pid = {p.get('ProcessId'): p.get('Name') or 'Unknown process' for p in rows(snapshot.get('processes'))}
        for item in rows(snapshot.get('listeners'))[:500]:
            scope = address_scope(item.get('LocalAddress'))
            listeners.append({'pid': item.get('OwningProcess'), 'application': by_pid.get(item.get('OwningProcess'), 'Unknown process'),
                              'address': item.get('LocalAddress'), 'port': item.get('LocalPort'), 'scope': scope,
                              'review': scope in ('all-interfaces', 'public')})
        due = parsed(self.reminder['dueAt'])
        recent = self.collections[-20:]
        return {'settings': dict(self.settings), 'freshness': fresh, 'sensors': sensors, 'findingStates': states,
                'collections': list(self.collections[-30:]), 'protectionChanges': list(self.changes[-30:]),
                'collectionHealth': {'samples': len(recent), 'failures': sum(not v['success'] for v in recent),
                                     'averageMs': round(sum(v['durationMs'] for v in recent) / len(recent)) if recent else None},
                'connectionDelta': dict(self.delta), 'connectionScopes': [address_scope(c.get('RemoteAddress')) for c in rows(snapshot.get('connections'))],
                'listeners': listeners, 'listenersTotal': len(rows(snapshot.get('listeners'))),
                'listenersAvailable': snapshot.get('listeners') is not None,
                'reminder': {**self.reminder, 'due': bool(due and now >= due)},
                'scope': 'Local metadata only. A listener does not prove remote reachability. Socket changes are sampled tuples, not stable process identities.'}


def markdown_report(report):
    """Render only the existing allowlisted report; never accept arbitrary strings."""
    system = report.get('platform') if report.get('platform') in ('Windows', 'Linux', 'Darwin') else 'unknown'
    lines = ['# Sentinel Local security summary', '', 'Platform: ' + system,
             '', 'This summary covers available sampled checks; it does not certify a clean computer.',
             '', '| Protection flag | State |', '| --- | --- |']
    status = report.get('collection', {}).get('freshness')
    status = status if status in ('fresh', 'stale', 'unknown', 'unverified') else 'unknown'
    lines[5:5] = ['', 'Observation freshness: ' + status + '. Stored flags may be historical when data is not fresh.']
    for key in FLAGS:
        value = report.get('protection', {}).get(key)
        lines.append('| ' + key + ' | ' + ('on' if value is True else 'off' if value is False else 'unknown') + ' |')
    lines += ['', '| Observation | Count |', '| --- | --- |']
    for key in SOURCES:
        if key not in ('firewall',):
            value = report.get('counts', {}).get(key)
            lines.append(f'| {key} | {value if type(value) is int and value >= 0 else "unknown"} |')
    lines += ['', 'Identifiers, paths, addresses, raw logs and exact observation times are excluded.',
              'Native security engines supply malware detection and blocking; AI advice remains advisory.', '']
    return '\n'.join(lines)
