// src/data/hamptonRoads757.js
//
// Polls local n8n webhooks (traffic, weather, WJCC news) for the Hampton
// Roads / Historic Triangle side panel. This is a plain polling service, not
// a map data layer — see ui.js's Hampton Roads panel for presentation.
// Adjust the URLs below to match your actual n8n webhook paths.

const SOURCES = [
  { kind: 'traffic', url: 'http://localhost:5678/webhook/757-traffic' },
  { kind: 'weather', url: 'http://localhost:5678/webhook/757-weather' },
  { kind: 'news', url: 'http://localhost:5678/webhook/757-wjcc-news' },
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

    const next = { traffic: [], weather: [], news: [] };
    let anySucceeded = false;
    let lastError = null;

    for (const src of SOURCES) {
      try {
        const res = await fetch(src.url);
        if (!res.ok) {
          lastError = `${src.kind} HTTP ${res.status}`;
          console.warn(`[HamptonRoads757] ${src.kind} returned ${res.status}`);
          continue;
        }
        const items = await res.json();
        if (!Array.isArray(items)) {
          lastError = `${src.kind} malformed response`;
          continue;
        }
        anySucceeded = true;
        next[src.kind] = items.filter((item) => item && typeof item === 'object');
      } catch (err) {
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
