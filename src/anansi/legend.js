/**
 * Ananzi LEGEND: one quick-reference card for every icon, colour and line the
 * Ananzi layers put on the globe, each with a plain-English line and the
 * technical term. Opened from the LEGEND chip in the bottom-right corner;
 * the Attack Map's BRIEF reuses the attack-map section.
 *
 * Personal research tooling: English-only by design (see scripts/i18n.mjs).
 */
// No imports from the layer modules: the legend is UI-shell code and must not
// pull Cesium in. The icons/colours below mirror THREAT_LAYERS
// (threatLayers.js) and KINDS (hamptonRoadsLayer.js); legend.test.mjs pins them.
export const LEGEND_LAYERS = Object.freeze([
  { id: 'cyber-botnet-c2', name: 'Botnet C2 Servers', icon: '☣', color: '#ff2b2b' },
  { id: 'cyber-reported-attackers', name: 'Reported Attackers', icon: '⚑', color: '#ff8a1f' },
  { id: 'cyber-ransomware', name: 'Ransomware Victims', icon: '☠', color: '#e0457b' },
  { id: 'cyber-internet-outages', name: 'Internet Outages', icon: '⚡', color: '#f4cf5e' },
  { id: 'cyber-outage-reports', name: 'Outage Reports', icon: '⚠', color: '#e8d9a8' },
  { id: 'cyber-ics-exposure', name: 'Exposed ICS', icon: '⚙', color: '#d4af37' },
  { id: 'exposed-cameras', name: 'Exposed Cameras', icon: '◉', color: '#e8a33c' },
]);
export const LEGEND_757 = Object.freeze({
  traffic: { label: 'Traffic', glyph: '🚦', color: '#ff8a1f' },
  roadwork: { label: 'Roadwork', glyph: '🚧', color: '#f4cf5e' },
  weather: { label: 'Weather', glyph: '⛈', color: '#e8d9a8' },
  ships: { label: 'Ships', glyph: '🚢', color: '#d4af37' },
  news: { label: 'News', glyph: '📰', color: '#e0457b' },
});

/**
 * Attack types (blocklist.de) — must match server/providers/anansi/attack-glossary.js
 * SERVICES colours (pinned by legend.test.mjs).
 */
export const ATTACK_TYPE_COLORS = Object.freeze({
  ssh: ['SSH break-in attempts', '#ff2b2b'],
  bruteforcelogin: ['Website login guessing', '#ff5a4a'],
  apache: ['Website attacks', '#f4cf5e'],
  mail: ['Email server attacks', '#ff8a1f'],
  imap: ['Mailbox break-ins', '#e8a33c'],
  ftp: ['File-server break-ins', '#c9a227'],
  sip: ['Phone-system attacks', '#e0457b'],
  bots: ['Spam bots', '#c04dd8'],
});

export const COLORS = Object.freeze({
  ddos: '#e0457b',
  malware: '#c04dd8',
  phishing: '#8fd46b',
  hijack: '#ffb000',
  target: '#ff2b2b',
});

const LAYER_TEXT = {
  'cyber-botnet-c2': ['Computers that give orders to infected machines (grouped by country).', 'abuse.ch Feodo Tracker botnet C2 IPs (Emotet, QakBot, Dridex…).'],
  'cyber-reported-attackers': ['Addresses other server owners reported for attacking them.', 'AbuseIPDB blacklist, confidence 100, grouped by country.'],
  'cyber-ransomware': ['Organisations a ransomware gang claims to have hit, by country.', 'ransomware.live recent leak-site victims.'],
  'cyber-internet-outages': ['Places where the internet went dark or degraded.', 'IODA (Georgia Tech) outage scores: BGP, active probing, darknet telescope.'],
  'cyber-outage-reports': ['Confirmed internet outages and their cause (power, cable cut, government shutdown).', 'Cloudflare Radar outage annotations.'],
  'cyber-ics-exposure': ['Industrial control systems answering openly on the internet. WORLD = how many per country; 757 = individual systems around Hampton Roads.', 'Shodan tag:ics — host/count facets (WORLD) or host/search (757).'],
  'exposed-cameras': ['How many cameras anyone can reach online, per country (or per 757 city). Counts only — no addresses or images.', 'Shodan host/count, camera screenshot label, country/city facets.'],
  'history-sundown-towns': ['Historical record from your own research file, coloured by strength of evidence.', 'Local dataset; Loewen/Tougaloo-style evidence ratings.'],
};

const SUNDOWN = [
  ['Surely (strong evidence)', '#c81e1e'],
  ['Probable', '#e0702a'],
  ['Possible', '#d4af37'],
  ['Unlikely', '#8a8a7a'],
  ['Not rated / unknown', '#a8842a'],
];

/** @typedef {{shape: 'dot'|'ring'|'pulse'|'glow'|'dash'|'dotted'|'glyph'|'chip', color: string, glyph?: string, label: string, plain: string, technical?: string}} LegendRow */

export function legendGroups() {
  return [
    {
      id: 'attack-map',
      title: 'ATTACK MAP',
      rows: [
        { shape: 'glyph', color: '#ff2b2b', glyph: '⌖', label: 'Attack source (crosshair)', plain: 'A country attacks are coming from, with a glowing arc into Hampton Roads — your vantage point, not a confirmed target. Bigger crosshair = more; its colour is the kind of attack it sends most.', technical: 'DShield top IPs + AbuseIPDB + sampled blocklist.de, AS-country geolocation; great-circle arc to 36.85, -76.29.' },
        ...Object.values(ATTACK_TYPE_COLORS).map(([label, color]) => ({ shape: 'dot', color, label: `Crosshair colour · ${label}`, plain: `Most of this country’s attacks are ${label.toLowerCase()}.`, technical: 'Dominant blocklist.de service among the country’s attacking IPs (48h).' })),
        { shape: 'glyph', color: '#ffffff', glyph: '•', label: 'Moving white dots', plain: 'Animation only — “missiles” riding an arc. Faster means more activity.', technical: 'Visual rate cue; not individual packets.' },
        { shape: 'dash', color: COLORS.ddos, label: 'Pink dashed arc', plain: 'DDoS: floods meant to knock websites or networks offline, from attacker country to target country.', technical: 'Cloudflare Radar L7/L3 top origin→target pairs, % of mitigated traffic (24h).' },
        { shape: 'dotted', color: COLORS.hijack, label: 'Amber dotted arc', plain: 'Internet route hijack: a network claimed someone else’s internet addresses and pulled their traffic toward itself.', technical: 'BGP hijack events (Cloudflare Radar), hijacker country → victim country.' },
        { shape: 'ring', color: COLORS.hijack, label: 'Amber ring', plain: 'Internet route leak: a network passed on directions it shouldn’t have, detouring traffic.', technical: 'BGP route leak events (Cloudflare Radar).' },
        { shape: 'glyph', color: COLORS.malware, glyph: '☣', label: 'Biohazard (malware servers)', plain: 'Malware control servers and hacking-toolkit servers in that country. Click for the malware names.', technical: 'ThreatFox botnet_cc IOCs + C2IntelFeeds (Cobalt Strike, Sliver…) + SSLBL, AS country.' },
        { shape: 'glyph', color: COLORS.phishing, glyph: '✉', label: 'Envelope (phishing)', plain: 'Fake login pages (phishing) hosted in that country, and which brand they impersonate.', technical: 'OpenPhish community feed, host resolved and geolocated.' },
        { shape: 'pulse', color: COLORS.target, label: 'Pulsing red target', plain: 'Hampton Roads — the vantage point every attack arc aims at.', technical: 'Fixed vantage 36.85, -76.29.' },
      ],
    },
    {
      id: 'focus',
      title: 'WORLD / 757 FOCUS (Cyber & Exposed layers)',
      rows: [
        { shape: 'chip', color: '#d4af37', glyph: '🌐', label: 'WORLD (default)', plain: 'The Cyber and Exposed layers show the whole planet. The attack map always shows the whole world.', technical: 'No geographic filter; Shodan layers use per-country counts.' },
        { shape: 'chip', color: '#d4af37', glyph: '⚓', label: '757', plain: 'Narrow the Cyber and Exposed layers to Hampton Roads / the US. (The attack map ignores this — it is always worldwide.)', technical: 'Client filter on country-level points (US / US states) + server-side Shodan geo filter (36.85,-76.29, 120 km).' },
      ],
    },
    {
      id: 'cyber',
      title: 'CYBER LAYERS',
      rows: LEGEND_LAYERS.filter((l) => l.id.startsWith('cyber-')).map((l) => ({
        shape: 'glyph',
        color: l.color,
        glyph: l.icon,
        label: l.name,
        plain: LAYER_TEXT[l.id]?.[0] || '',
        technical: LAYER_TEXT[l.id]?.[1] || '',
      })).concat([
        { shape: 'dot', color: '#d4af37', label: 'Dot size', plain: 'Bigger dot = more of it in that place.', technical: 'Log-scaled severity per layer.' },
      ]),
    },
    {
      id: 'cameras',
      title: 'CAMERAS',
      rows: LEGEND_LAYERS.filter((l) => l.id === 'exposed-cameras').map((l) => ({
        shape: 'glyph', color: l.color, glyph: l.icon, label: l.name, plain: LAYER_TEXT[l.id][0], technical: LAYER_TEXT[l.id][1],
      })),
    },
    {
      id: '757',
      title: 'HAMPTON ROADS 757',
      rows: Object.values(LEGEND_757).map((k) => ({
        shape: 'glyph', color: k.color, glyph: k.glyph, label: k.label, plain: `${k.label} items from your n8n flows / AIS, placed where they happen.`, technical: 'Items without coordinates are grouped (news at Williamsburg, weather at Norfolk).',
      })),
    },
    {
      id: 'history',
      title: 'HISTORICAL',
      rows: SUNDOWN.map(([label, color]) => ({ shape: 'dot', color, label: `Sundown towns · ${label}`, plain: 'Evidence level in your research file for that town’s historical sundown status.', technical: LAYER_TEXT['history-sundown-towns'][1] })),
    },
    {
      id: 'sky',
      title: 'SKY (STARS & PLANETS)',
      rows: [
        { shape: 'dot', color: '#fff3d6', label: 'Stars', plain: 'Each dot is a real star, placed over the spot on Earth it is directly above right now. Brighter stars are bigger; the whole sky drifts west about 15° every hour, so it moves in real time.', technical: 'd3-celestial J2000 catalogue (mag ≤ 5); sub-point = (dec, RA − GMST) from skyMath.js, recomputed every 20 s.' },
        { shape: 'dash', color: '#7a6a28', label: 'Constellation lines', plain: 'The stick-figure lines that join a constellation’s stars. Search a constellation by name to fly straight to it.', technical: 'd3-celestial constellation line-sets, split at the antimeridian so they never streak across the globe.' },
        { shape: 'glyph', color: '#ffcf3f', glyph: '☉', label: 'Sun', plain: 'The point on Earth the Sun is overhead right now (local solar noon).', technical: 'astronomy-engine equatorial position → sub-point, offline.' },
        { shape: 'glyph', color: '#e6e3d6', glyph: '☾', label: 'Moon', plain: 'The point the Moon is directly above right now.', technical: 'astronomy-engine, true equator-of-date.' },
        { shape: 'glyph', color: '#ff6b4a', glyph: '♂', label: 'Planets', plain: 'Mercury ☿, Venus ♀, Mars ♂, Jupiter ♃, Saturn ♄, Uranus ♅ and Neptune ♆ — each glyph sits over the spot that planet is overhead. Click one for its name and position.', technical: 'astronomy-engine per-body geocentric RA/Dec → sub-point.' },
      ],
    },
  ];
}

/** A small inline SVG for one legend row. */
export function swatchSvg(row) {
  const c = row.color;
  const svg = (inner) => `<svg viewBox="0 0 34 14" width="34" height="14" aria-hidden="true">${inner}</svg>`;
  switch (row.shape) {
    case 'dot':
      return svg(`<circle cx="17" cy="7" r="5" fill="${c}" stroke="#000" stroke-width="1.5"/>`);
    case 'ring':
      return svg(`<circle cx="17" cy="7" r="5" fill="none" stroke="${c}" stroke-width="2"/>`);
    case 'pulse':
      return svg(`<circle cx="17" cy="7" r="6" fill="none" stroke="${c}" stroke-width="1" opacity="0.5"/><circle cx="17" cy="7" r="3.5" fill="${c}"/>`);
    case 'glow':
      return svg(`<path d="M2 12 Q17 -2 32 12" fill="none" stroke="${c}" stroke-width="4" opacity="0.35"/><path d="M2 12 Q17 -2 32 12" fill="none" stroke="${c}" stroke-width="1.5"/>`);
    case 'dash':
      return svg(`<path d="M2 12 Q17 -2 32 12" fill="none" stroke="${c}" stroke-width="2" stroke-dasharray="5 3"/>`);
    case 'dotted':
      return svg(`<path d="M2 12 Q17 -2 32 12" fill="none" stroke="${c}" stroke-width="2.2" stroke-dasharray="1 3" stroke-linecap="round"/>`);
    default:
      return '';
  }
}

function el(doc, tag, cls, text) {
  const n = doc.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

/** Render legend groups (optionally only some) into DOM nodes. */
export function renderLegend(doc, { only } = {}) {
  const frag = doc.createDocumentFragment();
  for (const g of legendGroups()) {
    if (only && !only.includes(g.id)) continue;
    const sec = el(doc, 'section', 'ananzi-legend-group');
    sec.append(el(doc, 'h4', null, g.title));
    for (const r of g.rows) {
      const row = el(doc, 'div', 'ananzi-legend-row');
      const sw = el(doc, 'span', 'ananzi-legend-swatch');
      if (r.shape === 'glyph' || r.shape === 'chip') {
        sw.textContent = r.glyph || '•';
        sw.style.color = r.color;
        sw.classList.add(r.shape === 'chip' ? 'is-chip' : 'is-glyph');
      } else {
        sw.innerHTML = swatchSvg(r); // our own constant markup and colours
      }
      const body = el(doc, 'div', 'ananzi-legend-text');
      body.append(el(doc, 'b', null, r.label));
      if (r.plain) body.append(el(doc, 'p', 'attack-map-plain', r.plain));
      if (r.technical) body.append(el(doc, 'p', 'attack-map-tech', r.technical));
      row.append(sw, body);
      sec.append(row);
    }
    frag.append(sec);
  }
  return frag;
}

/** LEGEND chip in the corner row + its panel. */
export function initLegend(doc = document) {
  const row = doc.getElementById('corner-actions');
  if (!row || doc.getElementById('ananzi-legend-btn')) return () => {};
  const btn = el(doc, 'button', 'ananzi-focus-btn ananzi-legend-btn', '▦ LEGEND');
  btn.type = 'button';
  btn.id = 'ananzi-legend-btn';
  btn.title = 'What every icon, colour and line on the map means';
  btn.setAttribute('aria-expanded', 'false');
  const panel = el(doc, 'aside', 'ananzi-legend');
  panel.id = 'ananzi-legend';
  panel.hidden = true;
  panel.setAttribute('role', 'dialog');
  panel.setAttribute('aria-label', 'Map legend');
  const head = el(doc, 'div', 'ananzi-legend-head');
  const close = el(doc, 'button', 'threat-popover-close', '×');
  close.type = 'button';
  close.setAttribute('aria-label', 'Close legend');
  head.append(el(doc, 'span', null, 'LEGEND · WHAT’S ON THE MAP'), close);
  const body = el(doc, 'div', 'ananzi-legend-body');
  panel.append(head, body);
  const setOpen = (open) => {
    if (open) body.replaceChildren(renderLegend(doc));
    panel.hidden = !open;
    btn.setAttribute('aria-expanded', String(open));
    btn.classList.toggle('active', open);
  };
  btn.addEventListener('click', () => setOpen(panel.hidden));
  close.addEventListener('click', () => setOpen(false));
  const onKey = (e) => {
    if (e.key === 'Escape' && !panel.hidden) setOpen(false);
  };
  doc.addEventListener('keydown', onKey);
  row.prepend(btn);
  doc.body.append(panel);
  return () => {
    doc.removeEventListener('keydown', onKey);
    btn.remove();
    panel.remove();
  };
}
