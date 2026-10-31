# Hampton Roads Maritime — AIS for the 757 panel

Live ship tracking for Anansi, focused on the Port of Virginia, Naval Station Norfolk, and the bridge-tunnels.

God's Eye View already includes a live AIS vessel layer (`server/providers/vessels/`, `src/data/aisLiveVessels.js`) backed by [AISStream.io](https://aisstream.io). This module adds the Hampton Roads part:

1. **A regional subscription.** AISStream only streams ships inside the Hampton Roads box, which saves bandwidth and keeps the globe focused.
2. **A maritime feed for the 757 panel.** It reads the platform's `/api/vessels` endpoint, places each vessel in a port zone, and ranks what's worth showing:

| Severity | What it means |
| --- | --- |
| `high` | Search & rescue, law enforcement, medical, or military vessels broadcasting AIS |
| `medium` | Tankers, cargo, or passenger ships **moving through** the HRBT, the CBBT, or Thimble Shoal Channel |
| `low` | Other commercial traffic underway |
| `info` | Moored or anchored ships and small craft (counted in the summary, not listed) |

**Zones:** Naval Station Norfolk · Norfolk International Terminals · Virginia International Gateway · Hampton Roads Bridge-Tunnel · Chesapeake Bay Bridge-Tunnel · Newport News waterfront · Elizabeth River · Thimble Shoal Channel · Hampton Roads harbor · James River · Cape Henry approaches · Lower Chesapeake Bay. The boxes are approximate.

> Navy warships usually don't broadcast AIS, so the military count reflects only the vessels that do.

## Setup

### 1. Get a free AISStream key
Sign up at [aisstream.io](https://aisstream.io) and create an API key.

### 2. Add it to `.env`
Copy the lines from [`env.hampton-roads`](env.hampton-roads) into your Anansi `.env`. The key stays on the server; the browser only talks to `/api/vessels`.

```env
AISSTREAM_API_KEY=your-key-here
AISSTREAM_BOUNDING_BOXES=[[[36.75,-76.75],[37.45,-75.65]]]
AISSTREAM_SILENCE_TIMEOUT_MS=300000
```

Restart the dev server. Turn on **Live Vessels** in Data Layers, and ships should appear around Hampton Roads within a minute or two.

### 3. Add the feed to the 757 panel
Copy `hamptonRoadsMaritime.js` to `src/data/`, then in `src/data/hamptonRoads757.js`:

```js
import { createHamptonRoadsMaritimeFeed } from './hamptonRoadsMaritime.js';

const maritime = createHamptonRoadsMaritimeFeed({
  onUpdate: ({ items, summary, status, error }) => {
    // items: [{lat, lng, label, type: 'maritime', source, severity, timestamp, metadata}]
    // Merge them into the panel list next to traffic, weather and news.
    // summary.headline -> e.g. "142 vessels in Hampton Roads waters · 38 underway · 21 cargo, 6 tanker, 2 passenger"
    // status: 'live' | 'stale' (kept last good data) | 'key-required' | 'error'
  },
});
maritime.start();
```

Like the 757 panel fix, a failed poll never turns the feed off. It keeps the last good data, marks it `stale`, and retries with backoff (up to 5 minutes).

## Tests

```bash
node --test integrations/hampton-roads-maritime/hamptonRoadsMaritime.test.mjs
```

The tests cover ship-type families, zone lookup, severity ranking, the panel schema, and the poller's failure and recovery behavior. The module was also checked end to end: sample AISStream messages went through the platform's own `ais-store.js`, and the resulting rows went through this module.

## Data credit
Vessel data: [AISStream.io](https://aisstream.io). AIS is a public broadcast. The base platform already registers the AISStream credit in its "Data attribution" popover.
