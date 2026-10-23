"""Sharing-safe, allowlisted diagnostics. Raw observations never enter this shape."""
from collections import Counter
import os
from pathlib import Path
import platform
import datetime as dt
from workbench import freshness

from version import __version__


def state_directory():
    system = platform.system()
    if system == 'Windows':
        return Path(os.environ.get('LOCALAPPDATA', Path.home() / 'AppData' / 'Local')) / 'SentinelLocal'
    if system == 'Darwin':
        return Path.home() / 'Library' / 'Application Support' / 'SentinelLocal'
    return Path(os.environ.get('XDG_STATE_HOME', Path.home() / '.local' / 'state')) / 'sentinel-local'


def public_report(state, model):
    snapshot = state.get('snapshot') or {}
    defender = snapshot.get('defender') or {}
    threat_values = snapshot.get('threats') or []
    threat_values = threat_values if isinstance(threat_values, list) else [threat_values]
    threats = [t for t in threat_values if isinstance(t, dict)]
    allowed_flags = ['AntivirusEnabled', 'RealTimeProtectionEnabled', 'BehaviorMonitorEnabled', 'IsTamperProtected']
    def count(name):
        values = snapshot.get(name)
        if values is None:
            return None
        return len(values) if isinstance(values, list) else 1
    # Counts and known enum values only: no strings copied from processes,
    # errors, events, executable paths, Wi-Fi, neighbors, jobs, or the model.
    severity_counts = Counter(f.get('severity') for f in state.get('findings', []) if f.get('severity') in ('critical', 'warning', 'review', 'info'))
    system = snapshot.get('platform')
    return {'schema': 'sentinel-sharing-safe-v1', 'version': __version__,
            'platform': system if system in ('Windows', 'Linux', 'Darwin') else 'unknown',
            'collection': {'hasSnapshot': bool(snapshot), 'failedSourceCount': len(snapshot.get('errors') or []),
                           'hasCollectionError': bool(state.get('lastError')),
                           'freshness': 'unverified' if state.get('lastError') else freshness(snapshot.get('collectedAt'), dt.datetime.now(dt.timezone.utc))['status']},
            'protection': {key: defender.get(key) if type(defender.get(key)) is bool else None for key in allowed_flags},
            'counts': {name: count(name) for name in ('processes', 'connections', 'listeners', 'startup', 'threats')},
            'threatStatus': {'active': sum(t.get('IsActive') is True for t in threats),
                             'historicalInactive': sum(t.get('IsActive') is False for t in threats),
                             'unknown': sum(type(t.get('IsActive')) is not bool for t in threats)},
            'findings': dict(severity_counts),
            'model': {'samples': int(model.state['samples']), 'ready': model.state['samples'] >= 20,
                      'profiles': len(model.state['processes'])},
            'privacy': 'Identifiers, command lines, file paths, network addresses, tokens, raw errors, event messages, exact observation times, and detailed findings are excluded.'}
