// src/data/hamptonRoads757.js
//
// Polls local n8n webhooks (traffic, weather, WJCC news) for the Hampton
// Roads / Historic Triangle side panel. This is a plain polling service, not
// a map data layer — see src/anansi/panels.js for presentation.
//
// 0.3.0: the app's Content Security Policy blocks http://localhost:5678 from
// the browser, so webhooks go through the same-origin bridge
// /api/n8n/<webhook> (server/providers/anansi/n8n.js; N8N_WEBHOOK_BASE sets
// the n8n address). Adjust the webhook names to match your n8n paths.

import { buildMaritimePicture } from './hamptonRoadsMaritime.js';

const SOURCES = [
  { kind: 'traffic', url: '/api/n8n/757-traffic' },
  { kind: 'weather', url: '/api/n8n/757-weather' },
  { kind: 'news', url: '/api/n8n/757-wjcc-news' },
  // Optional sources: quietly absent until configured.
  // VDOT 511 work zones — import integrations/vdot-511/n8n-vdot-workzones.json into n8n.
  { kind: 'roadwork', url: '/api/n8n/vdot-workzones', optional: true, pick: (body) => body?.items },
  // Ships — the platform's own AISStream cache (AISSTREAM_API_KEY), ranked by port zone.
  { kind: 'ships', url: '/api/vessels?maxRows=20000', optional: true, pick: (body) => buildMaritimePicture(body?.rows).items },
];

const POLL_INTERVAL_MS = 45000;

/**
 * @typedef {Object} HamptonRoadsFeedState
 * @property {Array<Object>} traffic
 * @property {Array<Object>} weather
 * @property {Array<Object>} news
 * @property {number|null} lastUpdate
 * @property {string|null} error
 * @property {boolean} loading
 */

export function createHamptonRoads757Feed() {
  let _timer = null;
  let _refreshing = null;
  const _listeners = new Set();

  /** @type {HamptonRoadsFeedState} */
  let _state = {
    traffic: [],
    weather: [],
    news: [],
    roadwork: [],
    ships: [],
    lastUpdate: null,
    error: null,
    loading: false,
  };

  function setState(patch) {
    _state = { ..._state, ...patch };
    for (const listener of _listeners) listener(_state);
  }

  async function poll() {
    setState({ loading: true });

    const next = { traffic: [], weather: [], news: [], roadwork: [], ships: [] };
    let anySucceeded = false;
    let lastError = null;

    for (const src of SOURCES) {
      try {
        const res = await fetch(src.url);
        if (!res.ok) {
          if (src.optional) continue; // not configured yet — not an error
          lastError = `${src.kind} HTTP ${res.status}`;
          console.warn(`[HamptonRoads757] ${src.kind} returned ${res.status}`);
          continue;
        }
        const body = await res.json();
        const items = src.pick ? src.pick(body) : body;
        if (!Array.isArray(items)) {
          lastError = `${src.kind} malformed response`;
          continue;
        }
        anySucceeded = true;
        next[src.kind] = items.filter((item) => item && typeof item === 'object');
      } catch (err) {
        if (src.optional) continue;
        lastError = `${src.kind} fetch error`;
        console.warn(`[HamptonRoads757] failed to fetch ${src.kind}`, err);
      }
    }

    if (anySucceeded) {
      setState({ ...next, lastUpdate: Date.now(), error: null, loading: false });
    } else {
      // Keep whatever was last shown rather than blanking the panel on a
      // transient outage — only the error/loading flags change.
      setState({ error: lastError || 'All sources unavailable', loading: false });
    }
  }

  return {
    /** Start polling immediately, then on the interval. Idempotent. */
    start() {
      if (_timer) return;
      _refreshing = poll();
      _timer = setInterval(poll, POLL_INTERVAL_MS);
    },
    /** Stop polling (e.g. on teardown). */
    stop() {
      if (_timer) clearInterval(_timer);
      _timer = null;
    },
    /** Force an immediate refresh outside the normal interval. */
    refresh() {
      return poll();
    },
    /**
     * Subscribe to state changes. Immediately invoked with the current state.
     * @param {(state: HamptonRoadsFeedState) => void} listener
     * @returns {() => void} Unsubscribe function.
     */
    subscribe(listener) {
      _listeners.add(listener);
      listener(_state);
      return () => _listeners.delete(listener);
    },
    getState() {
      return _state;
    },
  };
}

const hamptonRoads757Feed = createHamptonRoads757Feed();

export default hamptonRoads757Feed;
