---
canonical: https://TVW-80.github.io/Ananasi-intel/anansi/
meta-description: A real-time geospatial intelligence dashboard for the Hampton Roads / Historic Triangle region, built on a self-hosted n8n ETL pipeline feeding a live CesiumJS 3D map. Covers automation engineering, data pipeline design, and full-stack integration.
meta-theme-color: #151515
title: Anansi — Real-Time Regional Intelligence Dashboard | Toure's Cybersecurity Mastery Portfolio
---

# Anansi — Real-Time Regional Intelligence Dashboard

# Overview

Anansi is a self-hosted, real-time geospatial dashboard for the Hampton Roads / Historic
Triangle region of Virginia (757 / 804 area codes). It combines a self-hosted **n8n**
automation server as the data ingestion and ETL layer with **God's Eye View**, an
open-source CesiumJS 3D globe visualization platform, to render live public data — traffic
incidents, weather alerts, and local news — as an interactive map layer.

The goal was to build something closer to a lightweight SOC-style situational awareness
tool than a static map: multiple independent data pipelines, normalized into a common
schema, polled on an interval, and rendered live without manual refresh.

| Component            | Description                                                |
| --------------------- | ------------------------------------------------------------ |
| Visualization Platform | CesiumJS-based 3D globe (God's Eye View, rebranded "Anansi") |
| Automation / ETL       | Self-hosted n8n, deployed via Docker                        |
| Traffic Data           | TomTom Traffic Incident + Flow APIs (v5), including live vehicle tracking |
| Weather Data           | NOAA / National Weather Service Alerts API                  |
| Local News             | Google News RSS, XML-parsed and geocoded by keyword match   |
| Custom Data Layer      | Hand-written CesiumJS module polling n8n webhooks           |
| Branding               | Custom UI theme, wordmark, and original spider-mark logo    |

---

# IMPLEMENTATION:

# [Environment Setup]

*The base platform is a Node.js/Vite application (God's Eye View), run locally on Windows
11. Setup involved installing Node 24.x, cloning the repository, and configuring a
`.env` file for API keys. A separate Docker Desktop installation (via Microsoft Store)
was required to self-host the automation layer — this required enabling virtualization
in the system BIOS, which was disabled by default.*

# [Self-Hosted Automation Server (n8n)]

*n8n was deployed as a Docker container (`docker.n8n.io/n8nio/n8n`), persisting workflow
data and credentials in a named Docker volume so state survives container restarts. This
serves as the ETL backbone: each data source gets its own workflow, triggered on-demand
by a webhook rather than a fixed schedule — meaning the pipeline only queries upstream
APIs when the dashboard is actually being viewed.*

![n8n workflow canvas — traffic, weather, and WJCC news pipelines, each independently triggered by webhook](../images/n8n-workflows.png)

# [Traffic Data Pipeline]

*A workflow pulls live incident data from TomTom's Traffic Incident Details API (v5)
scoped to a bounding box covering Norfolk, Virginia Beach, Chesapeake, Portsmouth,
Suffolk, Newport News, and Hampton. A Code node normalizes TomTom's GeoJSON response
(incident category, delay magnitude, affected roads) into a consistent
`{lat, lng, label, type, metadata}` schema shared across all data sources. Beyond
static incidents, the TomTom flow API also drives a live vehicle-tracking overlay —
individual moving vehicle markers rendered directly on real Williamsburg-area streets,
updating continuously rather than showing a fixed snapshot.*

![Traffic incidents feed, closures ranked by severity](../images/traffic-feed.png)

# [Weather Alerts Pipeline]

*NOAA's public Alerts API (`api.weather.gov`) required no API key, but does require a
descriptive `User-Agent` header — omitting it results in a 403, a common but
under-documented gotcha with NOAA's API. Since NWS alerts are issued by administrative
zone rather than coordinate, a lookup table maps known Hampton Roads localities to
approximate coordinates so alerts can still be plotted geospatially.*

# [Local News Pipeline — Historic Triangle]

*The original plan used a Williamsburg-based news outlet's RSS feed directly, but the
source actively blocks automated requests at the network level (bot protection),
returning a 403 regardless of request headers. The workaround was switching to a
location-filtered Google News RSS query, which required writing a raw regex-based XML
parser in the Code node rather than relying on n8n's built-in XML-to-JSON conversion —
the actual parsed object shape didn't match documented conventions and needed to be
inspected directly from the HTTP response to get right. Obituary and real-estate
listing noise was filtered out at the parsing stage to keep the feed relevant to a
situational-awareness use case.*

![Live local news feed, geocoded and filtered by keyword match](../images/news-feed.png)

# [Custom CesiumJS Data Layer]

*A dedicated JavaScript module polls all three n8n webhooks on a 45-second interval,
converts each normalized record into a Cesium point entity with a label, and renders
them as a single toggleable map layer. Malformed or missing-coordinate records are
skipped defensively rather than crashing the render loop. This was the piece of actual
application code added to the open-source base platform, wiring an external live data
pipeline into an existing 3D visualization engine.*

# [Rebrand: Anansi]

*The base platform was rebranded end-to-end — application name, color theme (black
background, red accents, gold text/headers), and a fully original spider-mark logo
designed for the project (inspired by the Anansi trickster-spider folklore figure, not
any copyrighted character). The rebrand touched the app title, header, favicon, and
theme variables throughout the codebase.*

![Anansi — final rebrand with live vehicle tracking, red/black/gold theme](../images/anansi-rebrand.png)

---

# Architecture
