// Generates n8n-vdot-workzones.json from vdotWorkZones.js so the n8n Code node
// always runs exactly the tested normalizer.  Run: node build-n8n.mjs
import { writeFileSync } from 'node:fs';
import { normalizeWzdx } from './vdotWorkZones.js';

const FEED_URL =
  'https://data.511-atis-ttrip-prod.iteriscloud.com/smarterRoads/workzone/workZoneJSON/current/workZone.json';

export const CODE_NODE_JS = `// Generated from integrations/vdot-511/vdotWorkZones.js — edit there, then run build-n8n.mjs
${normalizeWzdx.toString()}

const feed = $input.first().json || {};
if (!Array.isArray(feed.features)) {
  // Upstream failed (bad token, timeout, outage): answer with an empty, flagged
  // result instead of halting, so the panel keeps its last good data.
  return [{ json: { items: [], summary: null, error: feed.error ? String(feed.error.message || feed.error) : 'VDOT feed returned no features' } }];
}
return [{ json: { ...normalizeWzdx(feed, {}), error: null } }];
`;

export const workflow = {
  name: 'Anansi — VDOT 511 work zones (Hampton Roads)',
  nodes: [
    {
      parameters: { httpMethod: 'GET', path: 'vdot-workzones', responseMode: 'responseNode', options: {} },
      name: 'Webhook',
      type: 'n8n-nodes-base.webhook',
      typeVersion: 2,
      position: [0, 0],
      webhookId: '5b0f3a52-1c7e-4d0a-9a51-757000000511',
    },
    {
      parameters: {
        url: FEED_URL,
        sendQuery: true,
        queryParameters: { parameters: [{ name: 'token', value: '={{ $env.VDOT_SMARTERROADS_TOKEN }}' }] },
        sendHeaders: true,
        headerParameters: { parameters: [{ name: 'User-Agent', value: 'Anansi/1.0 (Hampton Roads situational awareness)' }] },
        options: { timeout: 30000 },
      },
      name: 'VDOT WZDx feed',
      type: 'n8n-nodes-base.httpRequest',
      typeVersion: 4.2,
      position: [240, 0],
      onError: 'continueRegularOutput',
    },
    {
      parameters: { jsCode: CODE_NODE_JS },
      name: 'Normalize to panel items',
      type: 'n8n-nodes-base.code',
      typeVersion: 2,
      position: [480, 0],
      alwaysOutputData: true,
    },
    {
      parameters: {
        respondWith: 'firstIncomingItem',
        options: { responseHeaders: { entries: [{ name: 'Access-Control-Allow-Origin', value: '*' }, { name: 'Cache-Control', value: 'no-store' }] } },
      },
      name: 'Respond',
      type: 'n8n-nodes-base.respondToWebhook',
      typeVersion: 1.1,
      position: [720, 0],
    },
  ],
  connections: {
    Webhook: { main: [[{ node: 'VDOT WZDx feed', type: 'main', index: 0 }]] },
    'VDOT WZDx feed': { main: [[{ node: 'Normalize to panel items', type: 'main', index: 0 }]] },
    'Normalize to panel items': { main: [[{ node: 'Respond', type: 'main', index: 0 }]] },
  },
  settings: { executionOrder: 'v1' },
};

if (import.meta.url === `file://${process.argv[1]}`) {
  writeFileSync(new URL('./n8n-vdot-workzones.json', import.meta.url), JSON.stringify(workflow, null, 2) + '\n');
  console.log('wrote n8n-vdot-workzones.json');
}
