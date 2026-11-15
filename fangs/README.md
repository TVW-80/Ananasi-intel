# FANGS — Fast Adversary Network Graphing Suite

A cyber-focused mode of Ananzi: a **link-analysis graph of adversary infrastructure** built from record-level public IOC feeds,
with a CAD-style **dispatch queue** beside it. Defensive awareness only — FANGS never connects to an indicator host.

```
cd fangs && npm install && npm start      # http://127.0.0.1:8757/   (FANGS_OFFLINE=1 for bundled data only)
npm test                                   # 71 tests, ~45 s (browser tests use headless Chrome if present)
npm run bench                              # replay P/R, nDCG, latency, layout; writes results/*.json
```

Needs Node ≥ 20. It is a Node server (SSE, server-side analytics), so it cannot be served from GitHub Pages like the rest of the repo.

## What it does

| Piece | Implementation |
|---|---|
| Sources | C2IntelFeeds, abuse.ch Feodo / ThreatFox / URLhaus, OpenPhish, DShield, Cloudflare Radar; GreyNoise + OTX per-IP when keyed |
| Enrichment | ASN/geo via Team Cymru (DNS TXT), RIPEstat fallback. If both fail the IP has **no** ASN edge; nothing is guessed |
| Graph | Nodes: `ip host family campaign asn victim`. Edges: `hosts`, `resolves-to`, `same-asn` (ip→asn membership), `attacks`. graphology |
| Provenance | Elements can only be created by `FangsGraph.ingest(record)`. Each node/edge cites record ids; `verifyProvenance()` re-runs the adapter on the stored raw record and checks it really yields that node/edge, and re-hashes every record |
| Analytics | Server-side Louvain communities (weights damp ASN hubs and fronting domains), degree + betweenness, ForceAtlas2 layout; cytoscape renders precomputed positions |
| Dispatch | SSE stream with replay (`Last-Event-ID`/`?since=`), queue `new → triaged → acknowledged` (strict, audited). High/critical auto-triage; acknowledging is a human action |
| Severity | 0–100 from CISA KEV 0.30, EPSS 0.20, corroboration 0.15, family weight 0.15, freshness 0.10, graph centrality 0.10. Critical requires vulnerability evidence |
| ATT&CK | Deterministic rule table → techniques, validated against the bundled STIX (v20.1, 867 techniques); tactics come from the STIX, not hard-coded |
| Narration | Deterministic English generator always runs first. Optional Groq/Cerebras upgrade (key server-side, paced, score-prioritised queue, 2.5 s timeout); LLM-suggested techniques are kept only if they validate against the STIX |

## Measured results (this build, this sandbox)

All numbers are produced by the test suite and written to `results/`. **Read "What these numbers are" below before quoting any of them.**

| Criterion | Result |
|---|---|
| Provenance | **100 % sourced, 0 fabricated**: real snapshot 305 nodes / 383 rels; synthetic 10 seeds, 1,440 nodes / 2,817 rels. Verifier negative controls (fabricated edge, stripped provenance, missing record, tampered payload) are all caught |
| Known-campaign replay, ingest fidelity | edge precision **1.000**, recall **1.000** vs. the edges the emitted records support (10 held-out seeds, includes junk/private-IP/duplicate rejection) |
| Known-campaign replay, vs. full simulated world | edge precision 1.000; edge recall mean **0.928** (min 0.906): the gap is edges no feed reports (hidden hosts' family links), by construction |
| C2-set reconstruction (Louvain, 6 campaigns, ~30 % of hosts unlabeled by any feed) | precision 0.983, recall 0.973, F1 **0.978** (min 0.959); ARI 0.946 |
| …hidden hosts only | recovery mean **0.898**, **worst seed 0.760** ← a real miss |
| …implied same-campaign pairs | pairwise precision 0.962, recall 0.948 (**worst seed 0.868**) |
| Dispatch ranking, nDCG vs severity-blind (arrival-order and random) | @10 **0.868** vs 0.20; @25 **0.790** vs 0.22; @50 **0.791** vs 0.26. Wins 10/10 seeds at every cutoff; worst seed 0.615 @10. Shuffled-score control: 0.19 (benchmark can fail) |
| Event → board (limit 5 s) | Timings vary per run; ranges below are across 4 full runs. SSE client: p50 0.8–1.0 ms, max 1.5–**118 ms** (one outlier run; 60 events, 305-node graph). Headless Chrome ingest→DOM: p50 17–54 ms, max 74–**167 ms** (20 events; includes ≈50 ms CDP polling granularity, so it is an upper bound) |
| 1k-node layout (limit 300 ms) | median 166–174 ms, max 181–214 ms over 9 timed runs per suite run (every individual run was under 300 ms). Louvain + betweenness on 1k nodes: median 229–241 ms (async, not in the event path) |
| ATT&CK | 1,602 emitted mappings across 362 events: 0 invalid; all rule-table techniques valid and not revoked/deprecated; bundle has 161 revoked/deprecated entries that the validator rejects |
| Suite | 71 tests, 0 skipped: provenance, adapters, replay, dispatch, ATT&CK, narration, perf, server/security, boundaries, theme (78 WCAG contrast pairs, both themes), i18n (en/es), browser E2E |

## What these numbers are (and aren't)

**Only two data sources were reachable from the build sandbox:** `raw.githubusercontent.com` (C2IntelFeeds, MITRE ATT&CK STIX). abuse.ch, OpenPhish, DShield, CISA, FIRST, RIPEstat, Team Cymru and Groq/Cerebras were refused by the network policy. Consequences:

1. **Real data = one feed, one family.** The bundled real snapshot (2026-11-15) is 226 Cobalt Strike C2 IPs + 78 domains. The resulting graph is a star: 1 family, 226 IPs, 78 hosts, **0 ASN nodes** (enrichment blocked). Louvain finds 48 clusters (modularity 0.256, one 180-node hub cluster), betweenness is degenerate (the family node = 1.0), and **all 294 real events score "low"** because C2IntelFeeds records carry no CVE, so KEV/EPSS contribute nothing. The board does not yet discriminate on real data; it needs CVE-bearing and multi-family feeds (ThreatFox/URLhaus with a key).
2. **Everything else is tested against format fixtures I wrote from the vendors' documented shapes** (`src/fixtures.js`, labelled synthetic; documentation IP ranges, `.example` domains). Field names for Feodo, ThreatFox, URLhaus, DShield, Radar, GreyNoise and OTX are **unverified against live responses**. Expect to fix small parse differences on first live run; the adapters are small and isolated, and parse failures are skipped, not fatal.
3. **The replay ground truth and the nDCG labels are synthetic and written by me.** The generator plants structure (shared domains, ASNs, hubs, fronting domains, junk) that Louvain is well suited to; thresholds were set from dev seeds 100–104 and reported on held-out seeds 1–10. This shows the pipeline recovers planted structure. It is **not** evidence of real-world detection accuracy. The nDCG labels depend partly on the same features the scorer uses, so beating a blind baseline is expected; real analyst triage outcomes are needed to measure real lift.
4. **KEV/EPSS values in use are a synthetic sample** (`data/fixtures/kev-epss.sample.json`) unless the live CISA/FIRST fetch succeeds; scores carry a `basis` field and the UI says so. The live KEV/EPSS fetch, Cymru DNS, RIPEstat and LLM calls are covered by injected-dependency tests only, never run live.
5. **"Event → board" starts when the record is in the process.** Feed polling is 15–60 min, so real freshness is bounded by feed publication and polling, not by FANGS's tens of milliseconds.
6. **UI was checked in headless Chrome only** (screenshots + DOM assertions), not on other browsers or touch devices.

## Safety and boundaries (enforced by tests)

- No raw sockets, subprocesses or scanners in server code; every URL literal is on a host allowlist; a network spy confirms indicator hosts are never contacted.
- Keys come only from the environment (`.env.example` lists them), are never in any API response or SSE frame, and a secret scan runs over the repo. `.env` and `*.key` are gitignored.
- Loopback by default; POST needs an `x-fangs` header; 4 KB body cap; strict CSP; client never uses `innerHTML` (hostile feed text renders as inert text: tested with an `<img onerror>` brand).
- Private/reserved IPs and malformed domains never become nodes. Fronting domains (legitimate sites abused as cover) are graphed with low community weight and never dispatched as threats.

## Layout

```
server.js            HTTP + SSE            src/pipeline.js     ingest → graph → events → bus
src/adapters/        one file per feed     src/graph.js        provenance-enforcing graph
src/provenance.js    record store+verify   src/analytics.js    Louvain, centrality, layout
src/attack.js        STIX + mapper         src/scoring.js      KEV/EPSS + severity
src/dispatch.js      CAD queue + nDCG      src/narrate.js      deterministic + LLM
src/fixtures.js      SYNTHETIC generators  src/eval.js         evaluation harness
data/                real snapshot + trimmed ATT&CK STIX + labelled fixtures
public/              board UI (cytoscape), locales en/es      test/  results/  scripts/
```

Credits: MITRE ATT&CK® (Apache-2.0 data bundle, trimmed); C2IntelFeeds by drb-ra; graphology; cytoscape.js. Part of the Ananzi project.
