# Ananzi — session handoff (1.0 website + 3.0 globe app)

Paste this whole file into a new chat to bring it up to speed. It is the single
source of truth for what Ananzi is, where the code lives, how to run and test
it, the conventions that keep the test suite green, what is built, what is
pending, and the rules the project holds itself to.

Last updated: 2026-11-03.

---

## 1. What Ananzi is

A personal OSINT / cyber-threat situational-awareness project for Hampton Roads,
Virginia ("the 757"), owned by GitHub user **TVW-80** (git identity
`whoXisXhe <watsontoure@gmail.com>`). Brand: the trickster-spider "Anansi,"
styled **Ananzi** in the UI. Theme is gold `#d4af37` / red `#c81e1e` on a warm
near-black; **no blue or cyan anywhere** (a script enforces this — see §5).

It is **strictly for the owner's own research.** Non-commercial, single-user.

Two deliverables, one GitHub repo (`github.com/TVW-80/Ananasi-intel`):

- **Ananzi 1.0 — the website** (`main` branch; also the `add-*` branches). A
  static site: a landing page, a "debrief" page of project entries, and an
  **AI Security Intelligence Dashboard** (a remake of CYBERMED1C/AI-Tracker).
  Lives under `ai-security/`, `integrations/`, `anansi/` in that branch and is
  published on GitHub Pages.
- **Ananzi 3.0 — the globe app** (`anansi-0.3.0` branch). A CesiumJS 3D globe:
  a fork/port of Bilawal Sidhu's "God's Eye View" (upstream **v0.3.0**) themed
  for Ananzi and loaded with cyber/OSINT map layers, an Attack Map, and
  live-camera layers. **This is where almost all recent work happened.**

---

## 2. Repo & branch map (all in `TVW-80/Ananasi-intel`)

| Branch | What | State |
|---|---|---|
| `main` | 1.0 website + AI Security Dashboard | live on GitHub Pages |
| `add-ai-security-dashboard` | the dashboard | **merged** (PR #1) |
| `add-kev-epss-and-maritime` | KEV+EPSS automation, Hampton Roads maritime (AIS), VDOT 511, Shodan exposure counts, 3D buildings | **PR #2 OPEN — owner has not said to merge** |
| `anansi-0.3.0` | the 3.0 globe app | active; everything below is here |
| `radial-hud-overhaul` | older experiment | ignore unless asked |

**Local machine:** Windows PC nicknamed **dubb-box**. The 3.0 app is cloned at
`C:\Users\watso\gods-eye-view` and run with `npm run dev`. Always `cd` into that
folder first (the owner has run git/npm from the home folder by mistake).
**n8n** runs in a Docker container named `n8n` (`docker start n8n`); its webhooks
are at `http://localhost:5678/webhook` and feed the "Hampton Roads 757" layer.

---

## 3. How to run and test the 3.0 app

- **Dev server:** `npm run dev` (Vite). In this cloud sandbox it was run as
  `FLIPPER_SERIAL=0 NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost npx vite --port 5199 --strictPort`.
- **Node** in the sandbox lives at the scratchpad `node_modules/node-linux-x64/bin`
  (prepend to PATH). The owner's machine uses Node 24.
- **Tests:** `npm test` runs the full suite (**~8,900 tests, currently all
  passing**) and takes **>10 minutes** — run it in the background (nohup, poll a
  log for `EXIT`), never in the foreground.
- **Targeted tests:** `node --test --test-reporter=tap <files>`.
- **Theme check:** `node scripts/anansi-theme.mjs --check` (must say "no
  blue/cyan left").
- **Package boundaries:** `npm run -s check:boundaries` (must pass).
- **i18n:** `node scripts/i18n.mjs` (every locale must read "complete").

---

## 4. Keys & configuration (POWER UP panel → `.env`, untracked)

The in-app **POWER UP** panel (the small gold spider, bottom-right) is the one
place to enter every key; it writes the repo-root `.env` (git-ignored) and the
dev server restarts itself. Keys stay **server-side**, are never logged or
committed. Registry lives in `src/keySetupCore.mjs`.

Keys and what they unlock:

- `GOOGLE_MAPS_API_KEY`, `TOMTOM_API_KEY` — already set by the owner.
- `CESIUM_ION_TOKEN`, `OPENAI_API_KEY`, `OPENSKY_CLIENT_ID/SECRET`,
  `AISSTREAM_API_KEY`, `GEMINI_API_KEY`, `MAPILLARY_CLIENT_TOKEN`, `FIRMS_MAP_KEY`,
  `LL2_API_TOKEN` — upstream God's-Eye-View features (optional).
- **Cyber / Attack Map:** `ABUSEIPDB_API_KEY` (free), `CLOUDFLARE_API_TOKEN`
  (free; user token, **Account → Radar → Read**), `SHODAN_API_KEY`,
  `ABUSECH_AUTH_KEY` (free; ThreatFox + URLhaus + MalwareBazaar + SSLBL),
  `OTX_API_KEY` (free), `GREYNOISE_API_KEY` (optional — **works keyless**, a key
  only raises the daily cap), `SHADOWSERVER_API_KEY`/`_SECRET` (requires
  Shadowserver to approve an access request — **pending**), `GITHUB_TOKEN`
  (optional, lifts rate limits).
- **US-state 511 cameras (BYOK, free developer keys, personal-use terms):**
  `CCTV_VIRGINIA_KEY`, `CCTV_ARIZONA_KEY`, `CCTV_NCAROLINA_KEY`.
- **Opt-in flags:** `SHODAN_EXPOSURE_SEARCH=1` (paid; exact ICS points near
  Norfolk), `CCTV_<ID>_ENABLED=1` for opt-in camera networks, `CCTV_<ID>_KEY`.

**Shodan reality check:** the exposure *counts* (Exposed ICS/Cameras layers and
the Attack Map exposure scoreboard) use Shodan's `host/count` with search
**filters**, which the **free tier does not allow** — so on a free key they come
back empty and the layer now says "needs a paid Shodan membership." The genuinely
free Shodan use is **InternetDB** (keyless): it enriches each attacking IP on the
Attack Map with that box's open ports and known CVEs.

---

## 5. Conventions that keep the suite green (read before editing the 3.0 app)

- **i18n:** user-facing strings go through `msg()`/`t()`/`tn()`; the three
  catalogs `src/i18n/locales/{es,ru,zh-CN}.json` must stay **complete** (add a
  translation for every new string). `src/anansi/**` and other English-only
  modules are listed in `scripts/i18n.mjs` `NOT_UI`, so Anansi layer code is
  English-only by design — no catalog entries needed there. Template text can
  opt out with `translate="no"`, code with `// i18n-ignore`.
- **Package boundaries:** every new module must be added to
  `scripts/package-boundaries.json` in the right group (Anansi layer modules go
  with `application-layer-construction`; the CCTV provider modules under
  `./server/providers/cctv`). `npm run -s check:boundaries` enforces it.
- **Theme:** keep to the gold/red palette; `scripts/anansi-theme.mjs --check`
  fails on any blue/cyan. `src/ui/styles/anansi.css` holds the Ananzi styles and
  is imported before `cyber.css` (cyber must stay the last import).
- **No Cesium text labels** (`src/noCesiumLabels.test.mjs`): on-globe glyphs use
  **billboards** (images) — see `src/anansi/markerIcons.js` which bakes a glyph
  into an SVG badge. DOM labels go through the overlay host.
- **Layer lifecycle contract:** `init/enable/disable/update/destroy/getStats`.
  A cyber layer's `getStats()` reports `KEY REQUIRED` when keyed-but-unset,
  `stale` (not an error) when it still shows records after a failed refresh, and
  the hard error only when it has nothing to show.
- Commit identity `whoXisXhe <watsontoure@gmail.com>`. Trailers currently in use:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` and a
  `Claude-Session:` line (match whatever the active session reminder says).

---

## 6. What is built in 3.0 (feature inventory, all on `anansi-0.3.0`)

Server providers: `server/providers/anansi/` — `attack-map.js`,
`attack-sources.js`, `attack-glossary.js`, `threat-intel.js`, `threat-feeds.js`,
`ai-sec-intel.js`, `n8n.js`, `sundown.js`, `flipper-serial.js`. CCTV packs:
`server/providers/cctv/worldPacks.js` (+ the existing pack set). Client layers:
`src/anansi/` — `attackMap.js`, `threatLayers.js`, `hamptonRoadsLayer.js`,
`sitrep.js`, `legend.js`, `markerIcons.js`, `focus.js`, `panels.js`,
`settingsMenu.js`, `consoleScene.js`, `sceneTheme.js`, `locations.js`.

- **Branding:** gold circuit-spider logo (`public/logo.svg`, pupil follows the
  cursor), gold **SETTINGS** spider button (game-style; hides all panels so only
  the globe + bottom dock + corner spiders show), gold classic-spider **POWER
  UP** button. UI name is **ANANZI**.
- **POWER UP** key panel (§4).
- **Cyber layers** (glyph billboards, colored per layer): Botnet C2 (☣),
  Reported Attackers (⚑), Ransomware Victims (☠), Internet Outages (⚡), Outage
  Reports (⚠), Exposed ICS (⚙), Exposed Cameras (◉, amber). Data from abuse.ch
  Feodo, AbuseIPDB, ransomware.live, IODA, Cloudflare Radar, Shodan.
- **Attack Map** (`cyber-attack-map`): **one fused world view** — every
  attacking country shows as a crosshair (⌖, colored by attack type) with a
  glowing arc into Hampton Roads; malware servers are biohazards (☣), phishing
  envelopes (✉), DDoS pink dashed arcs, BGP hijacks amber dotted arcs, leaks
  amber rings, a pulsing red target on Norfolk. Sources: SANS ISC/DShield,
  AbuseIPDB, blocklist.de (colors arcs by attack type), Cloudflare Radar
  (DDoS + BGP hijacks/leaks + industries), abuse.ch ThreatFox/URLhaus/
  MalwareBazaar/SSLBL, AlienVault OTX, GreyNoise, Shadowserver, Spamhaus DROP,
  Tor exit list, CISA KEV, CISA ICS advisories, FortiGuard RSS, FIRST EPSS,
  GitHub PoC watch, C2IntelFeeds, Malpedia, Shodan InternetDB + exposure counts.
  HUD: estimated live counter, attack-type legend, a rotating view (sources /
  ports / DDoS industries / DDoS targets / exploited now / exposed worldwide),
  the ticker, **BRIEF** (every alert in plain English + technical, a legend, and
  per-source live/key-required/stale status), and **SITREP**.
- **SITREP** (`src/anansi/sitrep.js`): a pop-up that **slowly rolls one plain-
  English card at a time** (pauses on hover), fusing the Attack Map alerts with
  the **AI Security Intelligence** feed (`/api/ai-sec-intel`). Each card: a short
  headline, a plain sentence a help-desk tech can read, a green **Do:** line, a
  quiet technical footnote, a "read more" link. KEV/exploited items roll first.
- **Every alert/ticker/popup leads with plain English**; technical detail is a
  secondary, dimmer line (`attack-glossary.js` holds the two-voice text,
  including MITRE ATT&CK and EPSS explanations).
- **WORLD / 757 focus chip** (bottom-right): scopes the **Cyber & Exposed
  layers** to the US/Hampton Roads. The Attack Map ignores it (always worldwide).
- **Hampton Roads 757** data layer (`local-hampton-roads-757`): plots the n8n
  feed (traffic, VDOT roadwork, weather, ships, WJCC news) on the map and owns
  the 757 side panel; turning it off stops the polling.
- **Sundown Towns (historical)** layer: loads a research dataset the owner
  supplies into `src/data/local_data/sundown/` (nothing bundled; colored by
  evidence level).
- **CCTV cameras:** ~20 official networks worldwide (upstream) **plus**
  `worldPacks.js`: New Zealand (on), and opt-in Scotland/Ireland/Utah/Iowa; and
  the **TravelIQ 511 states Virginia / Arizona / North Carolina** (BYOK, in the
  Cameras group, Virginia anchored on Hampton Roads).
- **LEGEND** button (bottom-right): a full key for every icon/color/line, each
  in plain + technical.
- Cesium ion credit line: transparent with a gold glow (kept visible, as Google/
  Cesium require).

1.0 website (`main` / PR #2): AI Security Intelligence Dashboard
(`ai-security/`, `scripts/update_intel.py`, `.github/workflows/update-ai-security.yml`),
`integrations/` (hampton-roads-maritime, vdot-511, osm-buildings), debrief
entries 008–011.

---

## 7. Known limits & caveats (tell the owner these honestly)

- **Many live feeds were never reachable from the build sandbox** (no open
  internet except GitHub/package registries). Loaders follow each service's
  documented shape and fail independently, but their live shapes are
  **unverified**. After enabling anything, check the Attack Map **BRIEF** panel
  (which lists each source as live / key-required / stale / error) and the camera
  picker, and report back. Several camera networks are opt-in for exactly this
  reason.
- **Shodan exposure counts need a paid membership** (free keys can't use search
  filters). InternetDB enrichment is the free Shodan win.
- **Shadowserver** honeypot data needs them to approve an access request (a draft
  request message was written for the owner to send); until then that source is
  just off.
- ransomware.live's free API is rate-limited (1 req/min) and often slow, so its
  layer may read **STALE** — that's the source, not a bug.
- PR #2 on the website is **open and unmerged**; do not merge without the owner.

---

## 8. Pending / open threads

- **"blue hood" and "open planter"** — the owner asked to integrate these; the
  names didn't resolve to known tools and a clarifying question is outstanding
  (best guesses offered: BlueHound / Blue Hydra; Openplanet / OpenPLC / Planet).
  Get a link or one-line description before building.
- Offered but not yet requested: SITREP auto-open when the Attack Map turns on,
  and moving/resizing SITREP; a T-Pot/own-sensor honeypot layer; more 511 states
  (each is a few lines in `worldPacks.js`); confirming the sundown dataset's
  columns once the owner loads it.
- Merge decision on website PR #2 is the owner's.

---

## 9. Hard rules (do not cross)

- **Strictly personal research**, non-commercial, single user.
- **Look, don't touch:** map and count exposed systems; never connect to,
  log into, or probe them.
- **Never surface the exposed-camera *feeds***: the "Exposed Cameras" layer is
  **counts only** (no IPs, no images, no streams) — those are misconfigured
  private cameras and watching them is off-limits. The CCTV layer only shows
  cameras agencies publish for the public.
- **No targeting a private individual.** Keep to aircraft, ships, networks and
  infrastructure.
- **Keys stay server-side**, never logged, never committed (`.env` untracked).
- **Don't bundle copyrighted data** (e.g. the Tougaloo/Loewen sundown-towns
  database); the layer only reads a dataset the owner supplies locally.
- Keep classification-style markings (the "TOP SECRET" HUD flavor) inside the
  owner's private build; never on anything published publicly.
