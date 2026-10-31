# Anansi integrations

Add-ons for the Anansi globe (built on [God's Eye View](https://github.com/bilawalsidhu/gods-eye-view)). Each folder has its own setup guide and tests.

| Folder | What it adds | Key needed |
| --- | --- | --- |
| [`hampton-roads-maritime/`](hampton-roads-maritime/) | Live ships around the port, Naval Station Norfolk and the bridge-tunnels, ranked for the 757 panel | Free [AISStream](https://aisstream.io) key |
| [`vdot-511/`](vdot-511/) | VDOT work zones and lane closures (WZDx), with bridge-tunnel restrictions flagged. n8n workflow included. | Free [SmarterRoads](https://smarterroads.vdot.virginia.gov/register) token |
| [`osm-buildings/`](osm-buildings/) | 3D buildings without Google billing: Google 3D through Cesium ion, or Cesium OSM Buildings | Free [Cesium ion](https://ion.cesium.com) token |

Run all tests:

```bash
for t in integrations/*/*.test.mjs; do node --test "$t"; done
```

## Already in the base platform: just turn them on

These sources already ship with God's Eye View. You don't need new code, just the layer toggle and in one case a key. Some were added after Anansi was forked, so if a layer is missing from your Data Layers panel, update your copy from God's Eye View.

| Source | Layer in Data Layers | Setup |
| --- | --- | --- |
| **Weather radar**: NOAA MRMS through nowCOAST, about 4-minute updates | Rain radar | None |
| **Lightning density**: NOAA nowCOAST | Lightning density | None |
| **Hurricane tracks**: NOAA NHC / CPHC advisories | Cyclone advisories | None |
| **Earthquakes**: USGS | Earthquakes (24h) | None |
| **Wildfires**: NASA FIRMS active fire detections | Active Fires | Free key: `FIRMS_MAP_KEY` from [firms.modaps.eosdis.nasa.gov/api/map_key](https://firms.modaps.eosdis.nasa.gov/api/map_key/) |
| **Fire perimeters**: NIFC WFIGS | Fire Perimeters | None |
| **Satellite imagery**: NASA GIBS, including HLS Sentinel-2 / Landsat and VIIRS true color | Recent Imagery | None |
| **Geocoded news fallback**: GDELT DOC 2.0 | Used automatically when Google News has no headlines | None |

Rain radar and Cyclone advisories are the most useful for Hampton Roads, since the region floods from both rain and storm surge. Turn them on next to your NWS alerts.
