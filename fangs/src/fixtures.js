// SYNTHETIC campaign generator with planted ground truth. NOT real threat data.
// IPs come from RFC 5737 documentation ranges, ASNs from the RFC 5398 documentation block, domains under .example.
// Emits raw payloads in each feed's documented format so the real adapters' parse()/extract() are exercised end to end.
//
// Difficulty built in (so recovery is not trivial):
//   - ~30% of each campaign's hosts are "hidden": no feed ever labels them with a family. They appear only in an
//     unlabeled DShield list and are linkable to their campaign only through shared domains and ASNs.
//   - Two shared "bulletproof" ASNs host ~20% of every campaign's visible hosts (cross-campaign glue).
//   - Two legitimate "fronting" domains resolve to hosts of several campaigns (flagged as fronting by the feed).
//   - Junk: malformed rows, private/loopback IPs, invalid domains and exact duplicates that must be rejected.
import { rng } from './util.js';

const FAMILIES = ['cobaltstrike', 'sliver', 'havoc', 'qakbot', 'emotet', 'mirai'];
const FAM_C2INTEL = { cobaltstrike: 'Cobalt Strike', sliver: 'Sliver', havoc: 'Havoc', qakbot: 'QakBot', emotet: 'Emotet', mirai: 'Mirai' };
const BRANDS = ['ExampleBank', 'SampleMail', 'DemoCloud', 'TestPay'];

function* ipPool() {
  for (const net of ['192.0.2', '198.51.100', '203.0.113']) for (let i = 1; i < 255; i++) yield `${net}.${i}`;
}

export function generateCampaigns({ seed = 1, campaigns = 6, hostsPerCampaign = 14, hiddenFrac = 0.3, sharedAsnFrac = 0.2 } = {}) {
  const R = rng(seed);
  const pick = (arr) => arr[Math.floor(R() * arr.length)];
  const pool = ipPool();
  const SHARED_ASNS = ['AS64508', 'AS64509'];
  const world = { campaigns: [], hostCampaign: {}, ipAsn: {}, hidden: new Set() };
  const c2intelIp = ['#ip,ioc'], c2intelDom = ['#domain,ioc,uri_path,ip'], dshield = [], feodo = [], tfox = [], urlh = [], phish = [];
  const truthObs = new Set();    // rel keys supported by emitted (valid) records
  const truthAll = new Set();    // rel keys true in the simulated world (incl. unobserved)
  const addObs = (t, a, b) => { truthObs.add(`${t}|${a}|${b}`); truthAll.add(`${t}|${a}|${b}`); };
  const addAll = (t, a, b) => truthAll.add(`${t}|${a}|${b}`);

  const nCamp = Math.min(campaigns, FAMILIES.length);
  for (let c = 0; c < nCamp; c++) {
    const fam = FAMILIES[c];
    const ownAsns = [`AS${64496 + c * 2}`, `AS${64497 + c * 2}`];
    const n = Math.max(6, hostsPerCampaign + Math.floor((R() - 0.5) * 6));
    const hosts = [];
    for (let i = 0; i < n; i++) {
      const ip = pool.next().value;
      const hidden = R() < hiddenFrac;
      const asn = R() < sharedAsnFrac ? pick(SHARED_ASNS) : pick(ownAsns);
      hosts.push({ ip, hidden, asn });
      world.hostCampaign[`ip:${ip}`] = fam; world.ipAsn[`ip:${ip}`] = asn; if (hidden) world.hidden.add(`ip:${ip}`);
    }
    // ensure at least 2 visible hosts so each campaign has a labeled anchor
    for (const h of hosts.slice(0, 2)) { h.hidden = false; world.hidden.delete(`ip:${h.ip}`); }
    const camp = { family: fam, hosts: hosts.map((h) => `ip:${h.ip}`), hidden: hosts.filter((h) => h.hidden).map((h) => `ip:${h.ip}`), domains: [] };
    world.campaigns.push(camp);

    // direct family labels for visible hosts (C2IntelFeeds IP list or Feodo/ThreatFox depending on family)
    for (const h of hosts) {
      const ipId = `ip:${h.ip}`;
      addAll('hosts', `family:${fam}`, ipId);               // true in the world
      if (h.hidden) { dshield.push({ rank: 1, source: h.ip, reports: 100 + Math.floor(R() * 900), targets: 10 + Math.floor(R() * 90), firstseen: '2026-11-01', lastseen: '2026-11-14' }); continue; }
      const k = R();
      if (fam === 'qakbot' || fam === 'emotet') {
        feodo.push({ ip_address: h.ip, port: 443, status: 'online', hostname: null, as_number: Number(h.asn.slice(2)), as_name: `SYNTH-${h.asn}`, country: 'ZZ', first_seen: '2026-11-02 10:00:00', last_online: '2026-11-14', malware: fam === 'qakbot' ? 'QakBot' : 'Emotet' });
        addObs('hosts', `family:${fam}`, ipId); addObs('same-asn', ipId, `asn:${h.asn}`);
      } else if (k < 0.5) {
        c2intelIp.push(`${h.ip},Possible ${FAM_C2INTEL[fam]} C2 IP`);
        addObs('hosts', `family:${fam}`, ipId);
      } else {
        tfox.push({ id: 1000 + tfox.length + c * 100000, o: { ioc_value: `${h.ip}:443`, ioc_type: 'ip:port', threat_type: 'botnet_cc', fk_malware: `win.${fam}`, malware_printable: FAM_C2INTEL[fam], confidence_level: 75, first_seen_utc: '2026-11-10 08:00:00', tags: `${fam},c2,campaign:${fam}-wave1`, reference: null } });
        addObs('hosts', `family:${fam}`, ipId); addObs('hosts', `campaign:${fam}-wave1`, ipId);
      }
    }
    // domains: each resolves to 2-3 campaign hosts (hidden hosts included -> they become linkable)
    const nDom = 3 + Math.floor(R() * 3);
    for (let d = 0; d < nDom; d++) {
      const dom = `${fam}-c2-${d}.example`;
      camp.domains.push(dom);
      const k = 2 + Math.floor(R() * 2);
      const picked = new Set();
      while (picked.size < Math.min(k, hosts.length)) picked.add(Math.floor(R() * hosts.length));
      addAll('hosts', `family:${fam}`, `host:${dom}`);
      let any = false;
      for (const idx of picked) {
        const h = hosts[idx];
        c2intelDom.push(`${dom},Possible ${FAM_C2INTEL[fam]} C2 Domain,/api/v${d},${h.ip}`);
        addObs('hosts', `family:${fam}`, `host:${dom}`); addObs('resolves-to', `host:${dom}`, `ip:${h.ip}`); any = true;
      }
      void any;
    }
    // every host's ASN membership is true in the world; enrichment records (below) make it observable
    for (const h of hosts) { addAll('same-asn', `ip:${h.ip}`, `asn:${h.asn}`); }
  }
  // fronting domains resolving to hosts of several campaigns
  for (const fd of ['cdn-front-a.example', 'cdn-front-b.example']) {
    const chosen = [];
    for (const camp of world.campaigns) chosen.push(pick(camp.hosts).slice(3));
    for (const ip of chosen) {
      const camp = world.hostCampaign[`ip:${ip}`];
      c2intelDom.push(`${fd},Possible ${FAM_C2INTEL[camp]} C2 Fronting Domain,/front,${ip}`);
      addObs('hosts', `family:${camp}`, `host:${fd}`); addObs('resolves-to', `host:${fd}`, `ip:${ip}`);
    }
  }
  // phishing records with victim brands (attacks edges)
  for (let i = 0; i < 8; i++) {
    const host = `login-${i}.phish.example`;
    const brand = pick(BRANDS);
    phish.push(JSON.stringify({ url: `https://${host}/signin`, brand }));
    addObs('attacks', `host:${host}`, `victim:${brand.toLowerCase()}`);
  }
  // junk that MUST be rejected / not create edges
  const junk = { c2intel: ['10.0.0.5,Possible Cobalt Strike C2 IP', '127.0.0.1,Possible Sliver C2 IP', 'not-an-ip,Possible Havoc C2 IP', ',', 'garbage line without comma'], dshield: [{ source: '192.168.1.9', reports: 5 }, { source: 'bad', reports: 1 }] };
  c2intelIp.push(...junk.c2intel);
  for (const j of junk.dshield) dshield.push(j);
  // exact duplicates (same record twice) must collapse
  if (c2intelIp.length > 4) c2intelIp.push(c2intelIp[2]);

  // enrichment records (what Team Cymru/RIPEstat would return) for every campaign IP
  const enrichment = Object.entries(world.ipAsn).map(([ipId, asn]) => ({ raw: { ip: ipId.slice(3), asn: asn.slice(2), prefix: null, cc: 'ZZ', registry: 'synthetic', as_name: `SYNTH-${asn}` }, retrieved_at: '2026-11-15T00:00:00Z', url: `fixture:synthetic-enrichment/${ipId.slice(3)}` }));
  for (const e of enrichment) { addObs('same-asn', `ip:${e.raw.ip}`, `asn:AS${e.raw.asn}`); }

  const u = (name) => `fixture:synthetic-campaign/seed-${seed}/${name}`;
  const payloads = [
    { source: 'c2intel', inputs: [{ file: 'IPC2s-30day.csv', text: c2intelIp.join('\n'), url: u('IPC2s-30day.csv') }, { file: 'domainC2swithURLwithIP-30day.csv', text: c2intelDom.join('\n'), url: u('domainC2swithURLwithIP-30day.csv') }] },
    { source: 'feodo', inputs: [{ text: JSON.stringify(feodo), url: u('feodo.json') }] },
    { source: 'threatfox', inputs: [{ text: JSON.stringify(Object.fromEntries(tfox.map((t) => [String(t.id), [t.o]]))), url: u('threatfox.json') }] },
    { source: 'openphish', inputs: [{ text: phish.join('\n'), url: u('openphish.txt') }] },
    { source: 'dshield', inputs: [{ text: JSON.stringify(dshield), url: u('dshield.json') }] },
  ];
  return { seed, payloads, enrichment, truth: { observable: [...truthObs].sort(), world: [...truthAll].sort(), hostCampaign: world.hostCampaign, ipAsn: world.ipAsn, hidden: [...world.hidden].sort(), campaigns: world.campaigns } };
}

// Labelled dispatch stream for the nDCG benchmark. HIDDEN relevance depends on features the scorer can see
// (KEV/EPSS/corroboration/family) AND on one it cannot (target-sector criticality) plus noise, so a perfect
// score is impossible. Labels are synthetic and written by the implementer: this benchmark demonstrates ranking
// mechanics, it does not measure real-world analyst agreement.
export function generateLabelledStream({ seed = 1, n = 300 } = {}) {
  const R = rng(seed);
  const gauss = () => { let s = 0; for (let i = 0; i < 6; i++) s += R(); return (s - 3) / 0.7071; };
  const famPool = [['cobaltstrike', 0.9], ['qakbot', 0.9], ['sliver', 0.8], ['mirai', 0.5], ['asyncrat', 0.5], [null, 0.25]];
  const out = [];
  for (let i = 0; i < n; i++) {
    const [family] = famPool[Math.floor(R() * famPool.length)];
    const kev = R() < 0.12 ? 1 : 0;
    const epss = kev ? 0.4 + R() * 0.6 : R() < 0.3 ? R() * 0.4 : 0;
    const sources = 1 + (R() < 0.3 ? 1 : 0) + (R() < 0.1 ? 1 : 0);
    const ageHours = R() * 120;
    const centrality = Math.pow(R(), 3);
    const sector = R();       // hidden from the scorer
    const latent = 1.0 * kev + 0.9 * epss + 0.4 * (sources - 1) + 0.5 * (family && ['cobaltstrike', 'qakbot', 'sliver'].includes(family) ? 1 : 0) + 1.3 * sector + 0.5 * centrality + 0.6 * gauss();
    out.push({ idx: i, features: { kev, epss, sources, family, ageHours, centrality }, latent });
  }
  // Quantile grades so the ideal ranking has a fixed shape: top 10% = 3, next 15% = 2, next 25% = 1, rest = 0.
  const order = [...out].sort((a, b) => b.latent - a.latent);
  order.forEach((e, rank) => { e.grade = rank < n * 0.10 ? 3 : rank < n * 0.25 ? 2 : rank < n * 0.50 ? 1 : 0; });
  for (const e of out) delete e.latent;
  return out;
}
