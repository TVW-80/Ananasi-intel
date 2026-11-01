# Sundown Towns (historical) — your data goes here

Anansi ships **no** sundown-town records. Put a research dataset you have the
right to use in this folder and turn on **Data Layers → Historical → Sundown
Towns (historical)**. Files here are git-ignored, so they stay on your machine.

## Recommended source

Rigby, Esposito, Lee, Van Riper, Hicken & Berrey (2025), *A national data set
of historical US sundown towns for quantitative analysis*, **Scientific Data**
12:31, https://doi.org/10.1038/s41597-024-04330-9 — the "Historical Sundown
Towns Linked to US Census Geographies" database. Follow the article's Data
Availability section to download it, and follow its license and citation terms.

The underlying research is James W. Loewen's Sundown Towns database at
Tougaloo College (https://justice.tougaloo.edu/sundown-towns/), copyrighted by
Loewen and heirs — use it for reading and citation, not for bulk copying.

## Accepted files

| File | Needs |
| --- | --- |
| `*.csv`, `*.tsv`, `*.txt` | a name column, plus **latitude/longitude** columns *or* a **GEOID** column |
| `*.geojson` / `*.json` | a FeatureCollection of Point features |
| Census Gazetteer places file (e.g. `2020_Gaz_place_national.txt`) | optional: lets rows with only a GEOID be placed on the map |

The Census Gazetteer file is free and public domain:
https://www.census.gov/geographies/reference-files/time-series/geo/gazetteer-files.html

Column names are matched case-insensitively:

- position: `latitude`/`lat`/`INTPTLAT`, `longitude`/`lon`/`lng`/`INTPTLONG`
- place: `name`/`town`/`place`/`city`, `state`/`STUSPS`
- evidence: `status`/`confidence`/`certainty`/`category`/`rating`
  (values like *surely*, *probable*, *possible*, *unlikely*, *don't know*)
- extras: `notes`/`description`, `source`/`citation`, `GEOID`

## How it's shown

Icons are colored by evidence level — red *surely*, orange *probable*, gold
*possible*, grey *unlikely*, dim gold for unrated — and stronger evidence gets
a larger icon. Every popover says it is a historical record of past practices
as documented by the source, not a statement about the place today.
