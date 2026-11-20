'use strict';
const $ = id => document.getElementById(id);
let evidence = Guardian.scenario('hatchling');
let selected = 'hatchling';
function text(id, value) { $(id).textContent = value; }
function paragraph(parent, value, cls) {
  const p = document.createElement('p'); p.textContent = value; if (cls) p.className = cls; parent.append(p);
}
function render() {
  const v = Guardian.evaluate(evidence);
  $('world').dataset.mood = v.mood;
  text('mode', v.demo ? 'DEMO · NO LIVE MONITORING' : 'IMPORTED EVIDENCE · NOT A LIVE CONNECTION');
  text('network', v.network); text('mood', v.expression[0]); text('headline', v.expression[1]); text('speech', v.expression[2]);
  text('protection', v.assessed ? `${v.passed} points verified` : 'Not assessed');
  $('pass-bar').style.width = `${v.passed}%`; $('fail-bar').style.width = `${v.failed}%`;
  text('score-detail', `${v.assessed}/100 assessed · ${v.failed} need attention · ${v.unknown} unknown. Owner-declared answers do not earn verified credit.`);
  text('comfort', {good: 'Connection looks good', degraded: 'Needs some care', unknown: 'Not measured'}[v.health.status]);
  text('health-detail', v.health.detail);
  text('awareness', v.radio.monitoring ? 'Observing a limited view' : 'View incomplete');
  text('radio-detail', v.radio.detail);
  text('coverage', `Bands: ${v.radio.bands.join(', ') || 'unknown'} · Channels: ${v.radio.channels.join(', ') || 'unknown'} · ${v.radio.fresh ? 'recent sample' : 'missing or stale sample'}`);
  text('source', `Source: ${v.source}. Configuration evidence expires after 7 days; radio/connection samples after 45 seconds. Weights are a prototype design, not a security standard.`);
  $('quests').replaceChildren();
  if (!v.quests.length) paragraph($('quests'), 'All selected configuration checks have current passing evidence. Keep observing; this does not cover every risk.');
  v.quests.slice(0, 3).forEach(c => { const div = document.createElement('div'); div.className = 'quest';
    const b = document.createElement('b'); b.textContent = c.name; div.append(b);
    paragraph(div, c.advice); const tag = document.createElement('span'); tag.textContent = c.status === 'fail' ? 'REVIEW OBSERVED SETTING' : 'GATHER EVIDENCE'; div.append(tag); $('quests').append(div); });
  $('checks').replaceChildren();
  v.checks.forEach(c => paragraph($('checks'), `${c.name} · ${c.weight} points · ${c.status} · ${c.basis}. ${c.detail}`));
  $('incidents').replaceChildren();
  if (!v.incidents.length) paragraph($('incidents'), 'No incident evidence in this sample. That does not establish that the network is safe.');
  v.incidents.forEach(i => {const div = document.createElement('div'); div.className = 'incident'; const h = document.createElement('h3');
    h.textContent = `${i.active ? 'Recent observation' : 'Historical observation'} · ${i.title}`; div.append(h); paragraph(div, i.detail); $('incidents').append(div);});
  document.querySelectorAll('[data-scenario]').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.scenario === selected)));
}
document.querySelectorAll('[data-scenario]').forEach(b => b.addEventListener('click', () => {
  selected = b.dataset.scenario; evidence = Guardian.scenario(selected); text('error', ''); render();
}));
async function readJSON(file) {
  if (file.size > 1024 * 1024) throw Error('Choose a JSON file smaller than 1 MiB.');
  return JSON.parse(await file.text());
}
$('evidence-file').addEventListener('change', async e => {
  try { const candidate = await readJSON(e.target.files[0]); Guardian.evaluate(candidate);
    evidence = candidate; selected = null; text('error', ''); render();
  } catch (err) { text('error', `Could not import evidence: ${err.message}`); }
});
$('snapshot-folder').addEventListener('change', async e => {
  try {
    const files = {};
    for (const f of e.target.files) if (['manifest.json', 'detector-health.json', 'sentinel-status.json'].includes(f.name)) {
      if (files[f.name]) throw Error('Choose a single snapshot folder.'); files[f.name] = await readJSON(f);
    }
    evidence = Guardian.antiHunterSnapshot(files); selected = null; text('error', ''); render();
  } catch (err) { text('error', `Could not import snapshot: ${err.message}`); }
});
$('export').addEventListener('click', () => {
  const url = URL.createObjectURL(new Blob([JSON.stringify(evidence, null, 2)], {type: 'application/json'}));
  const a = document.createElement('a'); a.href = url; a.download = evidence.demo ? 'guardian-demo.json' : 'guardian-evidence.json'; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
render();
// Demo sources tick only in memory; imported evidence always ages normally.
setInterval(() => { if (selected) evidence = Guardian.scenario(selected); render(); }, 3000);
