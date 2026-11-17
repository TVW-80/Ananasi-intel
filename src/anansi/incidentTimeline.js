/**
 * Incident timeline (client side, no Cesium).
 *
 * Builds the "reconstruction from public reporting" block shown in the News
 * Events popover. Honest by construction: the times are when a news index first
 * saw an article, never when anything happened, and the block says so.
 */

export const TIMELINE_DISCLAIMER =
  'Reconstructed from public reporting. Unverified. Times are when each article was first indexed, not when events happened.';

export function timelineRequestUrl(place) {
  return `/api/incident-timeline?place=${encodeURIComponent(String(place || '').trim())}`;
}

/** Group oldest-first entries into UTC hour buckets: [{ hour: '2026-11-14T15:00Z', entries }]. */
export function groupByHour(entries = []) {
  const buckets = new Map();
  for (const e of entries) {
    const t = Date.parse(e.time);
    if (!Number.isFinite(t)) continue;
    const hour = `${new Date(t).toISOString().slice(0, 13)}:00Z`;
    if (!buckets.has(hour)) buckets.set(hour, []);
    buckets.get(hour).push(e);
  }
  return [...buckets].map(([hour, items]) => ({ hour, entries: items }));
}

/** One-line summary above the timeline. */
export function summarizeTimeline(data) {
  if (!data || data.status === 'error')
    return data?.error || 'Timeline unavailable.';
  if (!data.entries?.length) return 'No matching reports in the last 72 hours.';
  const hours = Math.max(
    1,
    Math.round(
      (Date.parse(data.lastSeen) - Date.parse(data.firstSeen)) / 3_600_000,
    ),
  );
  return `${data.entries.length} report${data.entries.length === 1 ? '' : 's'} from ${data.sources} source${
    data.sources === 1 ? '' : 's'
  } over ~${hours}h`;
}

function el(tag, cls, value) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (value !== undefined) node.textContent = value;
  return node;
}

/** Render a timeline into `container` (textContent only, links limited to http/https by the server). */
export function renderTimeline(container, data) {
  container.replaceChildren();
  container.appendChild(
    el('div', 'incident-timeline-summary', summarizeTimeline(data)),
  );
  for (const bucket of groupByHour(data?.entries)) {
    container.appendChild(
      el('div', 'incident-timeline-hour', bucket.hour.replace('T', ' ')),
    );
    const list = el('ul', 'incident-timeline-list');
    for (const e of bucket.entries) {
      const li = el('li');
      const link = el('a', null, e.title);
      link.href = e.url;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      li.append(link, el('span', 'incident-timeline-domain', ` · ${e.domain}`));
      list.appendChild(li);
    }
    container.appendChild(list);
  }
  container.appendChild(
    el('div', 'incident-timeline-disclaimer', TIMELINE_DISCLAIMER),
  );
}

/** Fetch and render; resolves quietly on failure (the summary line carries the error). */
export async function loadTimeline(
  container,
  place,
  { fetchImpl = globalThis.fetch } = {},
) {
  container.replaceChildren(
    el('div', 'incident-timeline-summary', 'Building timeline…'),
  );
  try {
    const res = await fetchImpl(timelineRequestUrl(place), {
      cache: 'no-store',
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    renderTimeline(container, await res.json());
  } catch (err) {
    renderTimeline(container, {
      status: 'error',
      error: `Timeline failed: ${err?.message || err}`,
      entries: [],
    });
  }
}
