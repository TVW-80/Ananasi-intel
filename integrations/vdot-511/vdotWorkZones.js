/**
 * VDOT 511 Virginia work zones for the Anansi 757 panel.
 *
 * Input: VDOT's SmarterRoads WZDx v4 feed (GeoJSON FeatureCollection of
 * WorkZoneRoadEvent features — https://github.com/usdot-jpo-ode/wzdx).
 * Output: normalized panel items in the same shape as the n8n traffic,
 * weather and news pipelines: {lat, lng, label, type, source, severity,
 * timestamp, metadata}.
 *
 * The feed is statewide; this keeps Hampton Roads and the Historic Triangle,
 * drops events that aren't active right now, and flags anything touching a
 * bridge-tunnel or major water crossing.
 *
 * `normalizeWzdx` is deliberately self-contained (no imports, no closures over
 * module state) so build-n8n.mjs can paste it into an n8n Code node verbatim.
 */

export function normalizeWzdx(feed, options) {
  const opts = options || {};
  const now = opts.now ? new Date(opts.now) : new Date();
  const maxItems = opts.maxItems || 40;
  const SOURCE = 'VDOT 511 (SmarterRoads WZDx)';

  // Hampton Roads + Historic Triangle: [south, west, north, east]
  const REGION = opts.region || [36.55, -76.95, 37.45, -75.85];

  // Crossings where a closure backs up the whole region. Boxes are approximate.
  const CROSSINGS = [
    { id: 'hrbt', name: 'Hampton Roads Bridge-Tunnel (I-64)', box: [36.96, -76.335, 37.03, -76.28] },
    { id: 'mmmbt', name: 'Monitor-Merrimac Bridge-Tunnel (I-664)', box: [36.88, -76.43, 36.97, -76.37] },
    { id: 'elizabeth-tunnels', name: 'Downtown / Midtown Tunnels', box: [36.82, -76.32, 36.87, -76.285] },
    { id: 'james-river-bridge', name: 'James River Bridge (US-17)', box: [36.95, -76.5, 37.02, -76.44] },
    { id: 'cbbt', name: 'Chesapeake Bay Bridge-Tunnel (US-13)', box: [36.94, -76.15, 37.1, -75.95] },
  ];

  const inBox = (lat, lng, b) => lat >= b[0] && lat <= b[2] && lng >= b[1] && lng <= b[3];

  // GeoJSON coordinates are [lng, lat]; flatten LineString / MultiPoint / Point.
  const pointsOf = (geometry) => {
    if (!geometry || !geometry.coordinates) return [];
    const c = geometry.coordinates;
    if (geometry.type === 'Point') return [c];
    if (geometry.type === 'LineString' || geometry.type === 'MultiPoint') return c;
    if (geometry.type === 'MultiLineString') return c.flat();
    return [];
  };

  const CLOSED = new Set(['all-lanes-closed']);
  const RESTRICTED = new Set([
    'some-lanes-closed', 'some-lanes-closed-merge-left', 'some-lanes-closed-merge-right',
    'some-lanes-closed-split', 'alternating-one-way', 'flagging', 'temporary-traffic-signal',
  ]);
  const IMPACT_TEXT = {
    'all-lanes-closed': 'all lanes closed',
    'some-lanes-closed': 'lane closure',
    'some-lanes-closed-merge-left': 'lane closure, merge left',
    'some-lanes-closed-merge-right': 'lane closure, merge right',
    'some-lanes-closed-split': 'lane closure, split',
    'alternating-one-way': 'alternating one-way traffic',
    flagging: 'flagging operation',
    'temporary-traffic-signal': 'temporary signal',
    'all-lanes-open': 'all lanes open',
    'all-lanes-open-shift-left': 'lanes shifted left',
    'all-lanes-open-shift-right': 'lanes shifted right',
    unknown: 'impact unknown',
  };
  const DIR = { northbound: 'NB', southbound: 'SB', eastbound: 'EB', westbound: 'WB', 'inner-loop': 'Inner Loop', 'outer-loop': 'Outer Loop', undefined: '', unknown: '' };
  const RANK = { high: 0, medium: 1, low: 2 };

  const features = (feed && Array.isArray(feed.features)) ? feed.features : [];
  const items = [];
  let skippedInactive = 0;
  let skippedOutside = 0;

  for (const f of features) {
    const p = (f && f.properties) || {};
    const core = p.core_details || {};
    if (core.event_type && core.event_type !== 'work-zone') continue; // detours are linked events

    const start = p.start_date ? new Date(p.start_date) : null;
    const end = p.end_date ? new Date(p.end_date) : null;
    if ((start && start > now) || (end && end < now)) { skippedInactive += 1; continue; }

    const pts = pointsOf(f.geometry).filter((c) => Array.isArray(c) && isFinite(c[0]) && isFinite(c[1]));
    const inRegion = pts.filter(([lng, lat]) => inBox(lat, lng, REGION));
    if (!inRegion.length) { skippedOutside += 1; continue; }

    const crossing = CROSSINGS.find((x) => inRegion.some(([lng, lat]) => inBox(lat, lng, x.box))) || null;
    const impact = p.vehicle_impact || 'unknown';
    let severity = 'low';
    if (CLOSED.has(impact)) severity = 'high';
    else if (RESTRICTED.has(impact)) severity = crossing ? 'high' : 'medium';
    else if (crossing) severity = 'medium';

    const [lng, lat] = inRegion[Math.floor(inRegion.length / 2)];
    const road = (core.road_names || []).filter(Boolean).join(' / ') || 'Unnamed road';
    const dir = !core.direction ? '' : (core.direction in DIR ? DIR[core.direction] : core.direction);
    const where = crossing ? crossing.name
      : [p.beginning_cross_street, p.ending_cross_street].filter(Boolean).join(' to ');
    const label = `${road}${dir ? ' ' + dir : ''} — ${IMPACT_TEXT[impact] || impact}${where ? ' · ' + where : ''}`;

    items.push({
      lat, lng, label,
      type: 'roadwork',
      source: SOURCE,
      severity,
      timestamp: core.update_date || p.start_date || null,
      metadata: {
        source: SOURCE,
        severity,
        timestamp: core.update_date || p.start_date || null,
        id: f.id || null,
        road,
        direction: core.direction || null,
        vehicleImpact: impact,
        crossing: crossing ? crossing.id : null,
        crossingName: crossing ? crossing.name : null,
        description: core.description || null,
        start: p.start_date || null,
        end: p.end_date || null,
        workersPresent: p.worker_presence ? !!p.worker_presence.are_workers_present : null,
        reducedSpeedMph: isFinite(p.reduced_speed_limit_kph) ? Math.round(p.reduced_speed_limit_kph * 0.621371) : null,
      },
    });
  }

  items.sort((a, b) =>
    RANK[a.severity] - RANK[b.severity] ||
    (b.metadata.crossing ? 1 : 0) - (a.metadata.crossing ? 1 : 0) ||
    String(b.timestamp || '').localeCompare(String(a.timestamp || '')));

  const crossingsAffected = [...new Set(items.filter((i) => i.metadata.crossing && i.severity !== 'low').map((i) => i.metadata.crossingName))];
  return {
    items: items.slice(0, maxItems),
    summary: {
      active: items.length,
      closures: items.filter((i) => i.metadata.vehicleImpact === 'all-lanes-closed').length,
      crossingsAffected,
      skippedInactive,
      skippedOutside,
      feedUpdated: (feed && feed.feed_info && feed.feed_info.update_date) || null,
      headline: crossingsAffected.length
        ? `${items.length} active work zones · restrictions at ${crossingsAffected.join(', ')}`
        : `${items.length} active work zones in Hampton Roads · no restrictions at the crossings`,
    },
  };
}
