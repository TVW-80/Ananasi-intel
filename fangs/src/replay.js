// Demo/benchmark replay: streams the SYNTHETIC campaign fixture through the real pipeline at a fixed rate.
// Records keep origin "fixture:synthetic-campaign/..." so the UI can badge them as synthetic.
import { generateCampaigns } from './fixtures.js';

export function buildReplayRecords(fangs, { seed = 1 } = {}) {
  const camp = generateCampaigns({ seed });
  const recs = [];
  for (const p of camp.payloads) recs.push(...fangs.adapters.get(p.source).parse(p.inputs.map((i) => ({ ...i, retrieved_at: new Date().toISOString() }))));
  recs.push(...fangs.adapters.get('cymru').parse(camp.enrichment));
  return { recs, camp };
}

export function startReplay(fangs, { rateHz = 2, seed = 1 } = {}) {
  const { recs } = buildReplayRecords(fangs, { seed });
  let i = 0, stopped = false;
  const batch = Math.max(1, Math.round(rateHz / 10));
  const timer = setInterval(() => {
    if (stopped || i >= recs.length) { clearInterval(timer); return; }
    fangs.ingestRecords(recs.slice(i, i + batch)); i += batch;
  }, Math.max(20, 1000 / Math.max(rateHz / batch, 0.2)));
  timer.unref?.();
  return { stop: () => { stopped = true; clearInterval(timer); }, status: () => ({ total: recs.length, sent: Math.min(i, recs.length), running: !stopped && i < recs.length, synthetic: true, seed }) };
}
