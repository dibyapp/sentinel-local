'use strict';
const SentinelWorkbench = (() => {
  const element = id => document.getElementById(id);
  let current, services;
  const dirty = {reminder: false, retention: false};
  const filter = {query: '', severity: '', source: '', review: 'open', connection: '', scope: '', listener: ''};
  function findingMatches(finding, state, options) {
    if (options.severity && finding.severity !== options.severity) return false;
    if (options.source && finding.source !== options.source) return false;
    // Critical signals remain visible through review-state filters.
    if (options.review && finding.severity !== 'critical' && state !== options.review) return false;
    return !options.query || [finding.title, finding.detail, finding.source].join(' ').toLowerCase().includes(options.query.toLowerCase());
  }
  function scope(value) {
    const address = String(value || '').toLowerCase().split('%')[0];
    if (/^::ffff:\d+\./.test(address)) return scope(address.slice(7));
    if (address === '::1' || /^127\./.test(address)) return 'loopback';
    if (/^\d+\.\d+\.\d+\.\d+$/.test(address)) {
      const octets = address.split('.').map(Number);
      if (octets.some(v => v > 255)) return 'unknown';
      const [a, b] = octets;
      if (a === 0 || a === 10 || a === 169 && b === 254 || a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168 || a === 100 && b >= 64 && b <= 127 || a >= 224 || a === 192 && b === 0 || a === 198 && [18, 19, 51].includes(b) || a === 203 && b === 0) return 'local-or-reserved';
      return 'public';
    }
    if (/^(fc|fd|fe[89ab]|ff)/.test(address) || address === '::' || address.startsWith('2001:db8:')) return 'local-or-reserved';
    return /^[23][0-9a-f]{0,3}:/.test(address) ? 'public' : 'unknown';
  }
  function connectionMatches(connection, name, options) {
    return (!options.scope || (connection.scope || scope(connection.RemoteAddress)) === options.scope) && (!options.connection ||
      [name, connection.OwningProcess, connection.RemoteAddress, connection.RemotePort].join(' ').toLowerCase().includes(options.connection.toLowerCase()));
  }
  function block(title, text, className) {
    const {node} = services; const item = node('article', undefined, className || 'job');
    item.append(node('strong', title), node('p', text)); return item;
  }
  async function control(body) {
    try {
      await services.api('/api/control', body);
      if (body.action in dirty) dirty[body.action] = false;
      element('control-status').textContent = 'Saved locally.';
      await services.refresh();
    } catch (error) { element('control-status').textContent = error.message; }
  }
  function renderFindings(data) {
    current = data;
    if (!services) return;
    const {node} = services, list = element('finding-list'); list.replaceChildren();
    const findings = data.findings || [], states = data.workbench?.findingStates || {};
    const shown = findings.filter(f => findingMatches(f, states[f.reviewKey]?.status || 'open', filter));
    element('triage-count').textContent = `${shown.length} shown / ${findings.length} total; status totals include reviewed and snoozed findings.`;
    for (const f of shown) {
      const state = states[f.reviewKey] || {status: 'open'};
      const item = block(f.title, f.detail, 'finding ' + f.severity);
      item.append(node('small', `${f.source} · ${f.severity} · ${state.status}${state.until ? ' until ' + new Date(state.until).toLocaleString() : ''}`));
      if (f.severity !== 'critical' && f.reviewKey) {
        const actions = node('div', undefined, 'scan-options');
        for (const [status, title] of [['reviewed', 'Mark reviewed (7 days)'], ['snoozed', 'Snooze 1 hour'], ['open', 'Reopen']]) {
          if (state.status === status) continue;
          const button = node('button', title, 'subtle');
          button.addEventListener('click', () => control({action: 'finding', key: f.reviewKey, status})); actions.append(button);
        }
        item.append(actions);
      }
      list.append(item);
    }
    if (!shown.length) list.append(node('p', findings.length ? 'No findings match these filters. Counts and protection status are unchanged.' : 'No findings in the available checks. Review coverage before relying on this status.', 'empty'));
  }
  function renderConnections(data) {
    const {node} = services, snapshot = data.snapshot || {}, body = element('connections'); body.replaceChildren();
    const names = new Map((snapshot.processes || []).map(p => [p.ProcessId, p.Name]));
    const connections = (snapshot.connections || []).map((c, i) => ({...c, scope: data.workbench?.connectionScopes?.[i] || 'unknown'}));
    const matched = connections.filter(c => connectionMatches(c, names.get(c.OwningProcess) || '', filter));
    for (const c of matched.slice(0, 200)) {
      const row = node('tr'); row.append(node('td', names.get(c.OwningProcess) || `PID ${c.OwningProcess ?? 'unknown'}`), node('td', c.RemoteAddress), node('td', c.RemotePort)); body.append(row);
    }
    element('connection-count-label').textContent = snapshot.connections === null ? 'TCP source unavailable; empty inventory is not zero activity.' : `${Math.min(200, matched.length)} shown / ${matched.length} matching / ${connections.length} sampled. Address scope is an advisory classification.`;
  }
  function renderListeners(data) {
    const {node} = services, w = data.workbench, target = element('listeners'); target.replaceChildren();
    for (const listener of (w.listeners || []).filter(item => !filter.listener || item.review)) {
      target.append(block(`${listener.application} · ${listener.port}`, `${listener.address} · ${listener.scope}${listener.review ? ' · review binding' : ''}`));
    }
    element('listeners-note').textContent = !w.listenersAvailable ? 'Listener inventory is unavailable. Missing permission is not absence of services.' : `${w.listenersTotal} sampled listening sockets; at most 500 displayed. Binding to all interfaces is not proof of firewall exposure or remote reachability.`;
  }
  function render(data, helpers) {
    services = helpers; current = data; const w = data.workbench;
    element('local-controls').hidden = !w;
    if (!w) return;
    const {node} = services;
    renderFindings(data); renderConnections(data); renderListeners(data);
    const coverage = element('sensor-health'); coverage.replaceChildren();
    for (const sensor of w.sensors) coverage.append(block(sensor.name, sensor.status, 'sensor ' + (sensor.available && sensor.status === 'fresh' ? 'good' : 'warning')));
    element('freshness-label').textContent = `Observation: ${w.freshness.status}${w.freshness.ageSeconds === null ? '' : ' · ' + w.freshness.ageSeconds + ' seconds old'}`;
    const health = w.collectionHealth;
    element('collection-health').textContent = `${health.samples} recent collections · ${health.failures} failed · average ${health.averageMs ?? 'unknown'} ms. Collection errors remain visible; timings do not measure scanner speed.`;
    const timeline = element('collection-timeline'); timeline.replaceChildren();
    for (const sample of [...w.collections].reverse().slice(0, 10)) timeline.append(node('p', `${new Date(sample.at).toLocaleString()} · ${sample.durationMs} ms · ${sample.success ? sample.errors + ' source error(s)' : 'collection failed'}`));
    const changes = element('protection-changes'); changes.replaceChildren();
    for (const change of [...w.protectionChanges].reverse()) changes.append(block(change.field, `${String(change.before)} → ${String(change.after)} · ${new Date(change.at).toLocaleString()}`));
    if (!w.protectionChanges.length) changes.append(node('p', 'No protection-state transitions observed in this monitor session. Unknown states and restarts do not prove continuous protection.'));
    const delta = w.connectionDelta;
    element('connection-delta').textContent = delta.status === 'observed' ? `Since preceding successful sample: ${delta.opened} opened · ${delta.closed} closed · ${delta.persisting} persisting socket tuples. PID reuse and between-sample activity limit attribution.` : 'Two consecutive readable TCP samples are needed to compare activity.';
    element('learning-control').textContent = w.settings.learningPaused ? 'Resume baseline learning' : 'Pause baseline learning';
    element('learning-note').textContent = w.settings.learningPaused ? 'Learning is paused by you. Existing model checks and protection rules still run.' : 'Learning is enabled for readable observations. An initial baseline is not known-clean.';
    element('restore-baseline').disabled = !w.modelBackupAvailable;
    if (!dirty.retention && document.activeElement !== element('retention-days')) element('retention-days').value = String(w.settings.retentionDays);
    if (!dirty.reminder && document.activeElement !== element('reminder-days')) element('reminder-days').value = String(w.reminder.days);
    element('reminder-status').textContent = !w.reminder.days ? 'Reminders are off. No scan is scheduled.' : `${w.reminder.due ? 'Scan reminder due' : 'Next reminder'}: ${new Date(w.reminder.dueAt).toLocaleString()}. Open Sentinel to see reminders; no background notification or scan starts.`;
    element('reminder-done').disabled = !w.reminder.days;
    const jobList = element('job-timeline'); jobList.replaceChildren();
    const jobStatus = element('job-filter').value;
    for (const job of [...(data.jobs || [])].reverse().filter(item => !jobStatus || item.status === jobStatus)) {
      const start = new Date(job.startedAt), end = job.finishedAt ? new Date(job.finishedAt) : new Date();
      const seconds = Number.isFinite(end - start) ? Math.max(0, Math.floor((end - start) / 1000)) : 'unknown';
      jobList.append(block(`${job.action} · ${job.status}`, `${seconds} seconds${job.error ? ' · ' + job.error : ''}. ${job.status === 'running' ? 'A native engine can continue independently of this dashboard.' : ''}`));
    }
    if (!jobList.childNodes.length) jobList.append(node('p', 'No actions match this filter.'));
  }
  function init(helpers) {
    services = helpers;
    element('reminder-days').addEventListener('change', () => {dirty.reminder = true;});
    element('retention-days').addEventListener('change', () => {dirty.retention = true;});
    for (const [id, key] of [['finding-search', 'query'], ['finding-severity', 'severity'], ['finding-source', 'source'], ['finding-review', 'review'], ['connection-search', 'connection'], ['connection-scope', 'scope'], ['listener-filter', 'listener']]) {
      element(id).addEventListener(id.endsWith('search') ? 'input' : 'change', event => {filter[key] = event.target.value; if (current) render(current, services);});
    }
    element('job-filter').addEventListener('change', () => current && render(current, services));
    element('learning-control').addEventListener('click', () => control({action: 'learning', paused: !current.workbench.settings.learningPaused}));
    element('save-retention').addEventListener('click', () => {
      if (window.confirm('Apply this retention period to Sentinel collection history and advisory alerts? Older records are removed locally. Native engine history, scan jobs, AI journals and model profiles are unchanged.')) control({action: 'retention', days: Number(element('retention-days').value)});
    });
    element('save-reminder').addEventListener('click', () => control({action: 'reminder', days: Number(element('reminder-days').value)}));
    element('reminder-done').addEventListener('click', () => control({action: 'reminder-done'}));
    element('reset-baseline').addEventListener('click', () => {
      if (window.confirm('Restart learning? Sentinel keeps one private backup for Restore. A reset is not a malware cleanup or a trusted baseline; monitoring and native protection continue.')) control({action: 'baseline-reset', confirmed: true});
    });
    element('restore-baseline').addEventListener('click', () => {
      if (window.confirm('Restore the saved pre-reset baseline? Current learned samples are replaced. This cannot establish that the restored baseline is clean.')) control({action: 'baseline-restore', confirmed: true});
    });
    element('export-markdown').addEventListener('click', async () => {
      try {
        const response = await fetch('/api/report.md', {headers: {'X-Sentinel-Token': helpers.token}});
        if (!response.ok) throw Error('Summary export failed.');
        const url = URL.createObjectURL(new Blob([await response.text()], {type: 'text/markdown'}));
        const link = helpers.node('a'); link.href = url; link.download = 'sentinel-summary.md'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
      } catch (error) {element('control-status').textContent = error.message;}
    });
  }
  return {init, render, renderFindings, findingMatches, connectionMatches, scope};
})();
if (typeof module !== 'undefined') module.exports = SentinelWorkbench;
