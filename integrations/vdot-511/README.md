# VDOT 511 Virginia: work zones for the 757 panel

State-level road work data that complements TomTom: active Hampton Roads and Historic Triangle work zones from VDOT, with closures and restrictions at the **bridge-tunnels** called out.

It reads VDOT's [SmarterRoads](https://smarterroads.vdot.virginia.gov) feed, which is published in the federal **[WZDx v4](https://github.com/usdot-jpo-ode/wzdx)** (Work Zone Data Exchange) standard. Like your traffic, weather and news pipelines, it's an **n8n webhook workflow**, so the SmarterRoads token stays in n8n and VDOT is only called while the panel is open.

| Severity | Rule |
| --- | --- |
| `high` | All lanes closed anywhere, **or** any lane closure, alternating one-way, or flagging at a crossing |
| `medium` | Lane closures elsewhere, or lane shifts at a crossing |
| `low` | Other active work zones |

**Crossings watched:** HRBT (I-64), Monitor-Merrimac (I-664), Downtown/Midtown Tunnels, James River Bridge (US-17), Chesapeake Bay Bridge-Tunnel (US-13). The CBBT is run by its own district rather than VDOT, so expect it to show up rarely.

## Setup

1. **Get a SmarterRoads token.** Register at [smarterroads.vdot.virginia.gov/register](https://smarterroads.vdot.virginia.gov/register), then subscribe to the **Work Zone (WZDx)** data set. Your token is the `token=` value in the feed URL it gives you.
2. **Give n8n the token.** Add `VDOT_SMARTERROADS_TOKEN=<your token>` to the n8n container's environment, for example `-e VDOT_SMARTERROADS_TOKEN=...` in `docker run`, or under `environment:` in compose. Then restart n8n.
   - If your n8n blocks `$env` in expressions (`N8N_BLOCK_ENV_ACCESS_IN_NODE=true`), paste the token straight into the **token** query parameter of the "VDOT WZDx feed" node instead.
3. **Import the workflow.** In n8n, go to **Workflows → Import from File** and choose [`n8n-vdot-workzones.json`](n8n-vdot-workzones.json). Activate it.
4. **Poll it from the 757 panel**, the same way you poll the traffic, weather and news webhooks:

```js
const res = await fetch('http://localhost:5678/webhook/vdot-workzones');
const { items, summary, error } = await res.json();
// items: [{lat, lng, label, type: 'roadwork', source, severity, timestamp, metadata}]
// summary.headline -> "37 active work zones · restrictions at Hampton Roads Bridge-Tunnel (I-64)"
// error: null, or why the feed failed (items is [] — keep showing the last good list)
```

The workflow already has the fixes from your earlier n8n issues: the HTTP node continues on error, and the Code node has **Always Output Data** turned on. A bad token or a VDOT outage returns `{items: [], error}` instead of silently stopping the workflow.

## Files

| File | Purpose |
| --- | --- |
| `vdotWorkZones.js` | `normalizeWzdx(feed)`: WZDx → panel items. Can also be used directly in the app. |
| `build-n8n.mjs` | Writes the n8n workflow, pasting in the tested normalizer. Run `node build-n8n.mjs` after editing. |
| `n8n-vdot-workzones.json` | The workflow to import (Webhook → HTTP Request → Code → Respond). |
| `vdotWorkZones.test.mjs` | Tests: `node --test integrations/vdot-511/vdotWorkZones.test.mjs` |

The tests cover region filtering, active-time filtering, crossing detection, severity, labels, malformed feeds, and the generated Code node, including its error path. Set `WZDX_EXAMPLES=<clone of usdot-jpo-ode/wzdx>/examples/WorkZoneFeed` to also run the official WZDx example feeds through it.

## Incidents and cameras

SmarterRoads also offers incident and camera data sets. Their formats aren't publicly documented, so they aren't built here yet. Once you're subscribed, send me the incident feed URL (with the token removed) and I'll add a matching normalizer.
