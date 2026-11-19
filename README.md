Ananzi 3.0 & F.A.N.G.S
Nov 18, 2026 · @toure watson
Ananzi 3.0 is a private map of the world that runs in a web browser. It's built on a 3-D globe and centered on Hampton Roads (the “757” area in Virginia). It pulls in live public information — flights, ships, weather, news, and a lot of cyber-security data — and shows it on the globe. F.A.N.G.S is its cyber mode: a live “attack map” plus a dashboard that explains, in plain English, what's happening online right now. Everything it uses is public, most of it needs no password or key, and if one source goes down the rest keep working.
Ananzi 3.0 — the platform
Ananzi is a 3-D globe you can spin and zoom (built on a map engine called CesiumJS). It has a gold-and-red “757” look and a deliberately tactical, movie-like feel — but every source on it is public and real. Hampton Roads / Norfolk, VA is “home base,” the spot the view is built around. Nothing shows until you turn it on: each kind of data is its own layer with an on/off switch.
It can show a wide range of public data, each as its own on/off layer:
Domain
Layers
Where it comes from
Air
Live Flights, Military Flights, Local ADS-B
adsb.lol, OpenSky, adsbdb, a local receiver
Maritime
Live AIS Vessels
local AIS receiver
Space & sky
Satellites, Space Missions (30d), Sky (stars, planets & constellations, with the “Aje” star watch)
Celestrak TLEs, Launch Library, computed astronomy
Environment
Earthquakes (24h), FIRMS Active Fires, Fire Perimeters, Weather Alerts, Wind, Rain radar, Satellite clouds, Lightning density
USGS, NASA FIRMS, NOAA, NWS
Movement
Street Traffic, CCTV, Transit, Bikeshare, Recent Imagery
DOT camera networks, GTFS/GBFS, Mapillary
Signals & RF
GNSS Integrity, Radio, Flipper Detections
GNSS monitors, radio-browser, local Flipper hardware
Infrastructure
Mapped Installations, Datacenters, Dams, Submarine Cables, Exposed ICS, Exposed Cameras
OSM/curated data, Shodan exposure counts
Context
News Events, Hampton Roads 757, Global Context, Sundown Towns (historical)
GDELT, NWS, curated local data
Cyber
F.A.N.G.S and its sub-layers — Botnet C2 Servers, Reported Attackers, Ransomware Victims, Internet Outages, Outage Reports
covered below
The rest of this write-up is about the cyber mode.
F.A.N.G.S — the attack map
F.A.N.G.S stands for Fast Adversary Network Graphing Suite. It's the cyber layer: a live “pew-pew” attack map, like the ones you see on TV, plus a dashboard. Glowing lines (“arcs”) curve from where attacks are coming from toward Hampton Roads. Important: that does not mean Norfolk is being attacked — Hampton Roads is just the home point the lines aim at, and the sensors watch the whole world.
Here's what's drawn on the globe:
• Attack origins — Ananzi pulls big public lists of “bad” internet addresses (the computers doing the attacking) from several sources, removes duplicates, and looks up what city each one is in. That's why the map lights up with attackers all over the world instead of one dot per country.
• DDoS attacks — pink arcs show floods of junk traffic meant to knock websites offline, going from one country to another. (DDoS = Distributed Denial of Service.)
• Internet routing attacks — amber lines show “BGP” hijacks and leaks, where one network grabs or misdirects traffic that wasn't meant for it. BGP is the internet's road map; this is like someone rerouting the highway signs.
• Bad servers — markers for malware control servers (the computers hackers use to run infected machines, called “command-and-control” or C2) and for fake login / phishing pages.
You can click any line, dot, or marker. A pop-up explains it twice — plain English first, then the technical detail — and adds extra lookups about that address: GreyNoise (is this a machine that scans everybody, or one picking specific targets?), Shodan InternetDB (what's left exposed on the attacker's own computer), and VirusTotal (how many security vendors flag the address as bad). Only VirusTotal needs a key, and it's free.
A heads-up display sits on top: a running attack counter, a color key for attack types, and a panel that rotates through views (top source countries, most-attacked ports, industries getting hit, target countries, and what's exposed worldwide). A scrolling “ticker” moves at a steady pace with alerts from FortiGuard, AlienVault OTX, CISA (the U.S. cyber agency) and others. A BRIEF button opens the full detail for every alert, plus a legend and a live list of which sources are working.
Legend — reading the attack map
The in-app LEGEND button explains every marker. On the globe:
Marker
What it means
Source
⌖ Crosshair (red)
An attack source — a place attacks come from, with a glowing arc into Hampton Roads. Bigger crosshair = more; its colour is the attack type it sends most.
DShield + AbuseIPDB + blocklist.de, by AS-country
• Moving white dots
Animation only — “missiles” riding an arc. Faster = more activity (a rate cue, not individual packets).
visual only
Pink dashed arc
DDoS — floods meant to knock sites or networks offline, attacker country → target country.
Cloudflare Radar (L7/L3)
Amber dotted arc
Route hijack — a network claimed someone else's internet addresses and pulled traffic to itself.
Cloudflare Radar BGP
Amber ring
Route leak — a network passed on directions it shouldn't have, detouring traffic.
Cloudflare Radar BGP
☣ Biohazard
Malware control / hacking-toolkit servers (click for the malware names).
ThreatFox, C2IntelFeeds, SSLBL
✉ Envelope
Phishing hosts (fake login pages) and the brand they impersonate.
OpenPhish
Pulsing red target
Hampton Roads — the vantage point every arc aims at.
fixed (36.85, -76.29)
Each cyber sub-layer has its own symbol: ☣ botnet control servers (red), ⚑ reported attackers (orange), ☠ ransomware victims (pink), ⚡ internet outages (gold), ⚠ outage reports (tan), ⚙ exposed industrial control systems (gold), ◉ exposed cameras (amber). A WORLD / 757 toggle narrows the cyber and exposed layers down to Hampton Roads or back out to the whole planet; the attack map itself is always worldwide. Everywhere, a bigger dot means more of that thing in that place.
The one-pane SITREP dashboard
Opening F.A.N.G.S opens the SITREP — all of your cyber-security data in one pane of glass, written so a level-1/2 help-desk tech can read it at a glance. It stacks several live boards over a scrollable, plain-English card feed:
• ATT&CK HEAT — a live heat map of attacker “techniques.” MITRE ATT&CK is a free, industry-standard catalog of the moves hackers make (phishing, stealing passwords, and so on), each with a code like T1566. This board lists the techniques showing up right now, hottest first, and each one links to the official page that explains it.
• PATCH PRIORITY — a to-do list of which security holes to fix first. A “vulnerability” (or CVE) is a known weakness in software; CVSS is its 0–10 danger score. Items are sorted P1 (patch now), P2 (this cycle), or P3 (keep an eye on it). The key twist: something hackers are actively using right now jumps the line over something that only looks scary on paper — so a bug on CISA's “Known Exploited Vulnerabilities” (KEV) list beats a higher-scored bug nobody is using yet. You can collapse this board.
• SERVICE STATUS — the honest version of Downdetector. It reads the official status pages of a dozen big providers (Cloudflare, GitHub, Fastly, Discord, Zoom, Reddit, DigitalOcean, Datadog and more) and shows each as up, having trouble, or down — straight from the company, not from strangers complaining online.
• PASSWORD CHECK — checks a password against Have I Been Pwned's list of billions of passwords exposed in past breaches. It scrambles the password inside your browser first and sends only the first 5 characters of that scramble, so the real password never leaves your computer.
• Rolling cards — a scrolling feed that blends attack-map alerts, the cyber-news wire, AI-security news, and newly exploited bugs into one plain-English stream.
Click any threat and a worksheet opens on it. It runs that one event through the four tools analysts are trained to use: the Diamond Model (who attacked, what they used, from what infrastructure, and against whom), the Cyber Kill Chain (how far they got, from first scouting all the way to stealing data), the Pyramid of Pain (how hard it would be for the attacker to change this clue — an IP address is easy to swap, their whole way of operating is not), and a confidence score (how much to trust the tip, based on how fresh, how relevant, and how accurate it is).
RECON — event reconstruction
RECON is its own panel (a button in the F.A.N.G.S header, beside SITREP and BRIEF). It turns the live signal stream into reconstructed incidents rather than isolated alerts — the analyst's job of assembling what happened, in what order, by whom.
• Correlation — the tool groups separate alerts that share the same attacker, the same kind of move, and the same time window into a single “incident,” the way an analyst pieces one story together from scattered clues. For each incident it works out how far the attack got, which techniques were used, how hard the clues are to change, what infrastructure was involved, and an overall confidence that goes up when several independent sources agree.
• Narrative — a plain-English summary of the whole set of incidents, at the top of the panel.
• Timeline replay on the globe — a bar strip with a slider you can drag. Rewind it and the globe hides the live arcs and instead lights up the countries where things were reported as of that moment, growing as you slide forward. A badge on the map reads “◄ REPLAY · as of … · N countries.”
• Link-analysis graph — a connect-the-dots diagram linking attacker ↔ technique ↔ infrastructure ↔ malware ↔ bug ↔ victim, so infrastructure shared across different incidents stands out.
• Case-file export — a “copy case file” button copies a full written report (what happened, the technique links, the infrastructure, the timeline) to your clipboard so you can paste it elsewhere.
• Campaign detection — a RISING row that compares this week to last week and flags techniques climbing fast, an early sign that a campaign is forming.
Honesty is built in: correlation is labeled a hypothesis (co-occurrence, not confirmed attribution), the timeline is “as reported” rather than “as happened,” and replay pulses are country-level — signals with no country are counted as “+N off-map” rather than invented onto the map.
Intelligence frameworks
F.A.N.G.S sorts every event using the standard tools security analysts are trained on — the same ones on the CompTIA CySA+ certification exam — so the screen reads like real analyst work, not just a news feed.
Framework
What it answers
Where it shows up
MITRE ATT&CK
Which technique and tactic is this?
The live heat map, technique chips, and every event's mapping
Diamond Model of Intrusion Analysis
Adversary, capability, infrastructure, victim
The threat popover and the RECON link graph
Cyber Kill Chain (Lockheed)
How far did the intrusion get, across 7 phases?
The threat worksheet and each RECON incident
Pyramid of Pain
How painful is this indicator for the adversary to change?
The threat worksheet, per event
CySA+ confidence
How much should I trust this intel? (Timeliness · Relevance · Accuracy)
The worksheet, and lifted by corroboration at the incident level
Data sources and keys
Everything is public threat intelligence, mostly keyless. The feeds fall into a few groups:
Group
Feeds
Key needed?
Attacker IPs & arcs
SANS ISC / DShield, CINS Army, Emerging Threats, blocklist.de, abuse.ch Feodo, Spamhaus DROP, Tor exit list, AbuseIPDB, Cloudflare Radar (DDoS + BGP)
Keyless except AbuseIPDB, Cloudflare
Malware, C2 & phishing
abuse.ch ThreatFox, MalwareBazaar, SSLBL, C2IntelFeeds, OpenPhish, URLhaus, Malpedia
Mostly keyless (abuse.ch key optional)
Vulns & advisories
CISA KEV, FIRST EPSS, GitHub PoC watch, FortiGuard, CISA ICS advisories, Have I Been Pwned (breaches + Pwned Passwords)
Keyless
Per-IP enrichment
GreyNoise (Community), Shodan InternetDB, VirusTotal, MaxMind GeoLite2 / ip-api.com
GreyNoise & InternetDB keyless; VirusTotal needs a free key
The cyber-news wire aggregates 17 reputable RSS/Atom sources into the plain-English ticker: The Hacker News, BleepingComputer, Krebs on Security, The Record, SecurityWeek, CISA Advisories, Dark Reading, CyberScoop, Cybersecurity Dive, Cybersecurity Insiders, Industrial Cyber (ICS/OT), and the r/cybersecurity, r/blueteamsec and r/crowdstrike subreddits — plus Newsweek, BBC Technology and CNBC Technology, each filtered to cyber-only items so a mainstream outlet never floods the wire with sports or markets.
Keys are optional and handled through a POWER UP wizard. Nothing requires a key to run; a key simply switches one ingredient on (VirusTotal reputation, higher Cloudflare/Shodan limits). Keys live server-side in environment variables and are never committed. (Reuters and Downdetector are deliberately absent — neither offers a free public feed, and the project won't scrape.)
Design principles
A few rules run through the whole build:
• Honesty by construction. The tool never fakes detail it doesn't have. Replay is shown by country, not pretend address-by-address history; a grouped “incident” is clearly labeled a best guess, not proven fact; the timeline says “as reported,” not “as it truly happened.” It won't make up a risk score a feed didn't provide, won't pull from sources that forbid it, and won't impersonate anyone. When a signal can't be placed on the map or given a time, it's counted honestly instead of drawn in the wrong spot.
• Keyless-first. It works out of the box with public data; keys are optional, kept on the server, and only ever add one more ingredient.
• Graceful degradation. Each data source stands on its own. If one breaks, the tool keeps the last good copy, saves it to disk, and shows that rather than crashing. A missing key or an outage removes one ingredient — never the whole map.
• Built to last. Behind the scenes there are guardrails: data text kept English-only, strict limits on which parts of the code can touch which, a check that keeps the color theme consistent, and a large automated test suite (9,000+ tests) that every change has to pass before it ships.
Under the hood, Ananzi 3.0 lives in the TVW-80/Ananasi-intel code repository on the anansi-0.3.0 branch. The 3-D globe is drawn with CesiumJS (an open-source mapping engine), and a small web server sits behind it, fetching each data feed through its own cached web address (a /api/* endpoint) so the browser never talks to the outside feeds directly.
