'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const G = require('./model.js');
const now = Date.parse('2026-11-13T05:00:00Z');
test('all moods reflect independently measured dimensions', () => {
  for (const [scenario, mood] of Object.entries({hatchling:'curious',cozy:'cozy',legacy:'thoughtful',outage:'cloudy',alert:'alert',offline:'foggy'}))
    assert.equal(G.evaluate(G.scenario(scenario, now), now).mood, mood);
});
test('unknown controls never inflate the score', () => {
  const e = G.scenario('cozy', now); e.checks = e.checks.slice(0, 1);
  const v = G.evaluate(e, now); assert.equal(v.passed, 30); assert.equal(v.assessed, 30); assert.equal(v.unknown, 70);
});
test('owner declarations earn no verified credit', () => {
  const e = G.scenario('cozy', now); e.checks.forEach(c => c.basis = 'owner-declared');
  assert.equal(G.evaluate(e, now).passed, 0);
});
test('fresh endpoint does not prove the detector is running', () => {
  const e = G.scenario('cozy', now); e.radio.status = 'inactive';
  assert.equal(G.evaluate(e, now).mood, 'foggy');
});
test('missing, future and expired observations cannot keep eyes green', () => {
  for (const at of [undefined, 'bad', new Date(now + 60000).toISOString(), new Date(now - 45001).toISOString()]) {
    const e = G.scenario('cozy', now); e.radio.observed_at = at;
    assert.equal(G.evaluate(e, now).mood, 'foggy');
  }
});
test('configuration expires separately from telemetry', () => {
  const e = G.scenario('cozy', now); e.checks.forEach(c => c.checked_at = new Date(now - 8 * 86400000).toISOString());
  assert.equal(G.evaluate(e, now).passed, 0); assert.equal(G.evaluate(e, now).radio.monitoring, true);
});
test('historical incidents do not remain active forever', () => {
  const e = G.scenario('alert', now); e.incidents[0].observed_at = new Date(now - 300001).toISOString();
  assert.equal(G.evaluate(e, now).mood, 'cozy'); assert.equal(G.evaluate(e, now).incidents.length, 1);
});
test('a health failure does not delete verified security improvements', () => {
  const v = G.evaluate(G.scenario('outage', now), now); assert.equal(v.passed, 100); assert.equal(v.health.status, 'degraded');
});
test('duplicate control cannot award extra points', () => {
  const e = G.scenario('cozy', now); e.checks.push(e.checks[0]); assert.throws(() => G.evaluate(e, now), /Duplicate/);
});
test('unsupported schema and invented controls are rejected', () => {
  assert.throws(() => G.evaluate({schema:2}, now), /schema/);
  const e = G.scenario('cozy', now); e.checks[0].id = 'unhackable'; assert.throws(() => G.evaluate(e, now), /Unknown/);
});
test('AntiHunter snapshot never becomes a live sensor or a health probe', () => {
  const e = G.antiHunterSnapshot({'manifest.json':{collected_at:new Date(now).toISOString()},'detector-health.json':{state:{alerts:9}},'sentinel-status.json':{running:true}});
  const v = G.evaluate(e, now); assert.equal(v.demo, false); assert.equal(v.radio.monitoring, false); assert.equal(v.health.status, 'unknown'); assert.equal(v.passed, 0); assert.equal(v.incidents.length, 0);
});
test('older firmware with no sentinel endpoint remains unknown', () => {
  const e = G.antiHunterSnapshot({'manifest.json':{collected_at:new Date(now).toISOString()},'detector-health.json':{}});
  assert.match(G.evaluate(e, now).radio.detail, /unavailable/);
});
