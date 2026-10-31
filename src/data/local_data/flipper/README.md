# Flipper · Spider Sense detections

This folder feeds the **Flipper Detections** layer. Two ways to get data in.

## Live (while the dev server runs)

1. Flash the WiFi Dev Board with the SquachWatch Spider Sense sensor
   (`env:flipper-devboard`) and plug it onto the Flipper.
2. On the Flipper, run **USB-UART Bridge** (115200 baud) so the sensor's
   `SQW,*` lines reach the PC on its COM port. (qFlipper can't be open at the
   same time — only one program can hold the port.)
3. `npm i serialport @serialport/parser-readline` once, then `npm run dev`.
   The middleware (`src/data/flipperSerialProxy.js`) reads the port, appends a
   `capture-YYYY-MM-DD.csv` here, and serves the layer.
4. Enable **Flipper Detections** in Data Layers. Toggle it off/on to pull the
   latest (the local-GeoJSON layer loads once per enable).

Environment overrides: `FLIPPER_PORT` (default `COM3`), `FLIPPER_BAUD`
(`115200`), `FLIPPER_SERIAL=0` to disable the live read, `FLIPPER_HOME_LAT` /
`FLIPPER_HOME_LON` for the position live detections are stamped with when the
browser hasn't POSTed one to `/api/flipper/where`.

## Import (precise, GPS-accurate, no live link)

Drop two files directly in **this** folder:

- a detections **CSV** — a `capture-*.csv` from a live session, or a
  SquachWatch SD log (`ts,type,rssi,mac,channel,vendor,ssid`);
- a **GPX** track logged on your phone while walking with the Flipper.

Each detection is timestamp-matched to the nearest track point (within 60 s)
to get its lat/lon. Enable the layer to see them. See `samples/` for the exact
file shapes.

Captures (`*.csv`, `*.gpx`) here are git-ignored — only `samples/` and this
README are tracked.
