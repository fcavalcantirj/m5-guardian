/* Guardian's framework-independent evidence model. No radio or network actions. */
(function (root) {
  'use strict';
  const checks = [
    ['encryption', 'Modern encryption', 30, 'Check the actual WPA mode and cipher; prefer WPA3 where compatible.'],
    ['pmf', 'Management frame protection', 15, 'Check whether PMF is required, optional, or disabled.'],
    ['wps', 'WPS reviewed', 10, 'Review WPS in the router settings; a missing beacon field is not proof it is off.'],
    ['firmware', 'Router maintenance', 20, 'Compare the exact model and installed version with vendor support information.'],
    ['isolation', 'Guest isolation', 15, 'Verify the guest network boundary; a different network name is not enough.'],
    ['admin', 'Admin access', 10, 'Review the router admin password and remote-management exposure.']
  ];
  const moods = {
    curious: ['Curious', 'Let’s get to know our home.', 'I need more evidence before judging our protection.'],
    cozy: ['Cozy', 'A little peace of mind.', 'The checks I can observe look good. There is always more beyond my view.'],
    thoughtful: ['Thoughtful', 'A small improvement awaits.', 'I found a setting worth reviewing. We can learn about it together.'],
    alert: ['Alert', 'Something needs a closer look.', 'A recent observation needs review. The evidence is below.'],
    cloudy: ['Cloudy', 'Our connection needs some care.', 'A connection check is degraded. That alone does not tell me the cause.'],
    foggy: ['Foggy', 'My view is incomplete.', 'My radio observations are missing, inactive, or out of date.']
  };
  function validTime(value, now, maxAge) {
    const at = Date.parse(value);
    return Number.isFinite(at) && now - at >= -5000 && now - at <= maxAge;
  }
  function evaluate(input, now = Date.now()) {
    if (!input || typeof input !== 'object' || Array.isArray(input) || input.schema !== 1)
      throw Error('Expected a Guardian evidence file with schema: 1.');
    const supplied = Array.isArray(input.checks) ? input.checks : [];
    if (new Set(supplied.map(c => c.id)).size !== supplied.length) throw Error('Duplicate check IDs.');
    if (supplied.some(c => !checks.some(d => d[0] === c.id))) throw Error('Unknown configuration check.');
    const items = checks.map(([id, name, weight, advice]) => {
      const c = supplied.find(c => c.id === id) || {};
      const verified = ['observed', 'router-confirmed'].includes(c.basis)
        && validTime(c.checked_at, now, 7 * 86400000);
      const status = verified && ['pass', 'fail'].includes(c.status) ? c.status : 'unknown';
      return {id, name, weight, advice, status, basis: String(c.basis || 'unknown'),
        detail: String(c.detail || 'Not assessed.'), checked_at: c.checked_at || null};
    });
    const passed = items.filter(c => c.status === 'pass').reduce((n, c) => n + c.weight, 0);
    const failed = items.filter(c => c.status === 'fail').reduce((n, c) => n + c.weight, 0);
    const radio = input.radio || {};
    const fresh = validTime(radio.observed_at, now, 45000);
    const monitoring = fresh && radio.status === 'monitoring';
    const health = input.health || {};
    const healthFresh = validTime(health.observed_at, now, 45000);
    const healthState = healthFresh && ['good', 'degraded'].includes(health.status) ? health.status : 'unknown';
    const incidents = (Array.isArray(input.incidents) ? input.incidents : []).slice(-100).map(e => ({
      title: String(e.title || 'Observation'), detail: String(e.detail || ''), observed_at: e.observed_at || null,
      active: e.status === 'active' && validTime(e.observed_at, now, 300000)
    }));
    let mood = 'curious';
    if (incidents.some(e => e.active)) mood = 'alert';
    else if (!monitoring) mood = 'foggy';
    else if (healthState === 'degraded') mood = 'cloudy';
    else if (failed) mood = 'thoughtful';
    else if (passed >= 70 && healthState === 'good') mood = 'cozy';
    return {mood, expression: moods[mood], demo: input.demo === true,
      network: String(input.network || 'Network not selected'), source: String(input.source || 'Unknown source'),
      passed, failed, unknown: 100 - passed - failed, assessed: passed + failed, checks: items,
      radio: {fresh, monitoring, detail: String(radio.detail || 'No current radio evidence.'),
        observed_at: radio.observed_at || null, bands: Array.isArray(radio.bands) ? radio.bands.map(String) : [],
        channels: Array.isArray(radio.channels) ? radio.channels.map(String) : []},
      health: {status: healthState, detail: String(health.detail || 'No connection probe configured.')}, incidents,
      quests: items.filter(c => c.status !== 'pass').sort((a,b) => (b.status === 'fail') - (a.status === 'fail'))
    };
  }
  function scenario(name, now = Date.now()) {
    const at = new Date(now).toISOString();
    const e = {schema: 1, demo: true, source: 'Simulated home · no devices contacted', network: 'Casa do Brow',
      checks: checks.map(([id]) => ({id, status: 'pass', basis: 'observed', checked_at: at, detail: 'Simulated verified check.'})),
      radio: {status: 'monitoring', observed_at: at, bands: ['2.4 GHz'], channels: [6], detail: 'Demo observer · channel 6 only; 5 GHz not observed.'},
      health: {status: 'good', observed_at: at, detail: 'Demo Wi-Fi probe: gateway and HTTPS check succeeded.'}, incidents: []};
    if (name === 'hatchling') e.checks = [];
    else if (name === 'legacy') {
      e.checks.find(c => c.id === 'encryption').status = 'fail';
      e.checks.find(c => c.id === 'encryption').detail = 'Demo: legacy WPA/TKIP observed. Review router security.';
      e.checks.find(c => c.id === 'pmf').status = 'unknown';
    } else if (name === 'outage') {
      e.health = {status: 'degraded', observed_at: at, detail: 'Demo: gateway responds; external HTTPS check fails. Cause not established.'};
    } else if (name === 'alert') {
      e.incidents.push({title: 'Disconnect-frame burst', detail: 'Demo fixture: repeated deauth/disassoc frames on channel 6. Review scope and client impact.', observed_at: at, status: 'active'});
    } else if (name === 'offline') {
      e.radio.observed_at = new Date(now - 90000).toISOString();
      e.radio.detail = 'Demo: observer stopped reporting 90 seconds ago.';
    } else if (name !== 'cozy') throw Error('Unknown demo scenario.');
    return e;
  }
  function antiHunterSnapshot(files) {
    const h = files['detector-health.json'];
    const manifest = files['manifest.json'];
    if (!h || !manifest || !Number.isFinite(Date.parse(manifest.collected_at)))
      throw Error('Choose a defense snapshot containing detector-health.json and manifest.json.');
    const s = files['sentinel-status.json'];
    const state = h.state || {};
    return {schema: 1, demo: false, source: 'AntiHunter saved snapshot', network: 'Network not established by snapshot',
      checks: [], health: {status: 'unknown', detail: 'Detector uptime/heap are sensor diagnostics, not Wi-Fi connection health.'},
      radio: {status: 'unknown', observed_at: manifest.collected_at, bands: [], channels: [],
        detail: `Saved snapshot, not a live heartbeat. Sentinel reported: ${s?.running === true ? 'running' : s?.running === false ? 'stopped' : 'unavailable'}. Stored alerts: ${Number.isFinite(state.alerts) ? state.alerts : 'unknown'}. Band/channel coverage is unverified.`},
      incidents: []};
  }
  const api = {checks, moods, evaluate, scenario, antiHunterSnapshot};
  if (typeof module !== 'undefined') module.exports = api;
  else root.Guardian = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
