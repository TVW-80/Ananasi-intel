// src/data/aiSecIntelFeed.js
//
// Client polling service for the AI Security Intelligence panel. Plain
// subscribe/render service (same shape as hamptonRoads757.js) — not a map
// layer. The dev-server proxy (/api/ai-sec-intel → src/data/aiSecIntel.js)
// does the heavy lifting and caches for hours, so polling here is cheap.

const ENDPOINT = '/api/ai-sec-intel';
const POLL_INTERVAL_MS = 15 * 60_000;
const FETCH_TIMEOUT_MS = 30_000;

/**
 * @typedef {Object} AiSecState
 * @property {Object|null} snapshot  Last good /api/ai-sec-intel payload.
 * @property {number|null} lastUpdate  Client time of the last successful poll.
 * @property {string|null} error
 * @property {boolean} loading
 */

export function createAiSecIntelFeed() {
  let _timer = null;
  let _inflight = null;
  const _listeners = new Set();

  /** @type {AiSecState} */
  let _state = { snapshot: null, lastUpdate: null, error: null, loading: false };

  function setState(patch) {
    _state = { ..._state, ...patch };
    for (const listener of _listeners) listener(_state);
  }

  async function poll() {
    if (_inflight) return _inflight;
    setState({ loading: true });
    _inflight = (async () => {
      try {
        const res = await fetch(ENDPOINT, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const snapshot = await res.json();
        if (!snapshot || !Array.isArray(snapshot.vulns)) throw new Error('malformed response');
        setState({ snapshot, lastUpdate: Date.now(), error: null, loading: false });
      } catch (err) {
        // Keep whatever was last shown rather than blanking the panel on a
        // transient outage — only the error/loading flags change.
        setState({ error: err?.message || 'unavailable', loading: false });
      } finally {
        _inflight = null;
      }
    })();
    return _inflight;
  }

  return {
    /** Start polling immediately, then on the interval. Idempotent. */
    start() {
      if (_timer) return;
      void poll();
      _timer = setInterval(poll, POLL_INTERVAL_MS);
    },
    stop() {
      if (_timer) clearInterval(_timer);
      _timer = null;
    },
    refresh() {
      return poll();
    },
    /**
     * Subscribe to state changes; the listener is invoked immediately with the
     * current state.
     * @param {(state: AiSecState) => void} listener
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

const aiSecIntelFeed = createAiSecIntelFeed();

export default aiSecIntelFeed;
