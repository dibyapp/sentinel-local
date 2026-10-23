'use strict';
const assert = require('node:assert/strict');
const ui = require('../static/workbench.js');
const finding = {title: 'Fictional connection', detail: 'Sampled activity', source: 'Local behavior model', severity: 'review'};
assert.equal(ui.findingMatches(finding, 'open', {query: 'CONNECTION', severity: '', source: '', review: 'open'}), true);
assert.equal(ui.findingMatches(finding, 'open', {query: 'absent'}), false);
assert.equal(ui.findingMatches(finding, 'snoozed', {review: 'open'}), false);
assert.equal(ui.findingMatches(finding, 'reviewed', {review: 'reviewed', source: 'Security checks'}), false);
assert.equal(ui.findingMatches({...finding, severity: 'critical'}, 'open', {review: 'snoozed'}), true);
assert.equal(ui.findingMatches({...finding, severity: 'critical'}, 'open', {severity: 'warning'}), false);
const connection = {OwningProcess: 7, RemoteAddress: '8.8.8.8', RemotePort: 443, scope: 'public'};
assert.equal(ui.connectionMatches(connection, 'Fictional Browser', {scope: 'public', connection: 'browser'}), true);
assert.equal(ui.connectionMatches(connection, 'Fictional Browser', {scope: 'local-or-reserved'}), false);
assert.equal(ui.connectionMatches(connection, '', {connection: '443'}), true);
assert.equal(ui.connectionMatches({...connection, scope: 'unknown'}, '', {scope: 'public'}), false);
assert.equal(ui.scope('::ffff:127.0.0.1'), 'loopback');
assert.equal(ui.scope('fe80::1%fictional'), 'local-or-reserved');
assert.equal(ui.scope('invalid'), 'unknown');

// Regression: a background refresh must not discard a pending settings choice.
const elements = new Map();
function node(tag, text) {
  return {textContent: text || '', value: '', childNodes: [], listeners: {},
    append(...items) {this.childNodes.push(...items);}, replaceChildren() {this.childNodes = [];},
    addEventListener(event, handler) {this.listeners[event] = handler;}};
}
global.document = {activeElement: null, getElementById(id) {
  if (!elements.has(id)) elements.set(id, node('div'));
  return elements.get(id);
}};
const data = {findings: [], jobs: [], snapshot: {processes: [], connections: []}, workbench: {
  sensors: [], listeners: [], collections: [], protectionChanges: [], listenersAvailable: false,
  freshness: {status: 'fresh', ageSeconds: 1}, collectionHealth: {samples: 1, failures: 0, averageMs: 1},
  connectionDelta: {status: 'unavailable'}, settings: {learningPaused: false, retentionDays: 30},
  reminder: {days: 0, due: false}, findingStates: {}
}};
let calls = [];
const helpers = {node, async api(path, body) {calls.push({path, body}); data.workbench.reminder.days = body.days;}, async refresh() {ui.render(data, helpers);}};
ui.init(helpers); ui.render(data, helpers);
const reminder = document.getElementById('reminder-days');
assert.equal(reminder.value, '0');
reminder.value = '7'; reminder.listeners.change(); ui.render(data, helpers);
assert.equal(reminder.value, '7');
const retention = document.getElementById('retention-days');
retention.value = '90'; retention.listeners.change(); ui.render(data, helpers);
assert.equal(retention.value, '90');
global.window = {confirm: () => false};
document.getElementById('reset-baseline').listeners.click();
document.getElementById('save-retention').listeners.click();
assert.equal(calls.length, 0);
document.getElementById('save-reminder').listeners.click();
assert.deepEqual(calls[0], {path: '/api/control', body: {action: 'reminder', days: 7}});
setImmediate(() => {
  data.workbench.reminder.days = 1; ui.render(data, helpers);
  assert.equal(reminder.value, '1');
  assert.equal(retention.value, '90');
  console.log('20 dashboard assertions passed: filters, critical visibility, pending settings, cancellation and save.');
});
