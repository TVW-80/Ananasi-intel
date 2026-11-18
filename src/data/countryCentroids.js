/**
 * Ananzi — approximate country centroids (ISO-3166 alpha-2 → [lat, lon]).
 *
 * Deliberately coarse: used only to place a country-level pulse on the globe
 * during RECON replay, where the claim is "a signal attributed to this country
 * was reported", never a precise location. Client-side twin of the server's
 * countryCentroid (threat-feeds.js), kept small — the adversary countries that
 * actually show up in the feeds.
 */
const CENTROIDS = Object.freeze({
  US: [39.8, -98.6], CA: [56.1, -106.3], MX: [23.6, -102.5], BR: [-14.2, -51.9],
  AR: [-38.4, -63.6], CL: [-35.7, -71.5], CO: [4.6, -74.3], PE: [-9.2, -75.0],
  GB: [54.0, -2.0], IE: [53.4, -8.2], FR: [46.2, 2.2], DE: [51.2, 10.4],
  NL: [52.1, 5.3], BE: [50.5, 4.5], ES: [40.0, -3.7], PT: [39.4, -8.2],
  IT: [41.9, 12.6], CH: [46.8, 8.2], AT: [47.5, 14.6], PL: [51.9, 19.1],
  CZ: [49.8, 15.5], RO: [45.9, 24.9], UA: [48.4, 31.2], RU: [61.5, 105.3],
  SE: [60.1, 18.6], NO: [60.5, 8.5], FI: [63.2, 25.8], DK: [56.3, 9.5],
  TR: [38.9, 35.2], IR: [32.4, 53.7], IQ: [33.2, 43.7], SA: [23.9, 45.1],
  AE: [23.4, 53.8], IL: [31.0, 34.9], EG: [26.8, 30.8], ZA: [-30.6, 22.9],
  NG: [9.1, 8.7], KE: [-0.0, 37.9], MA: [31.8, -7.1], DZ: [28.0, 1.7],
  IN: [20.6, 79.0], PK: [30.4, 69.3], BD: [23.7, 90.4], CN: [35.9, 104.2],
  HK: [22.4, 114.1], TW: [23.7, 121.0], JP: [36.2, 138.3], KR: [35.9, 127.8],
  KP: [40.3, 127.5], VN: [14.1, 108.3], TH: [15.9, 101.0], MY: [4.2, 101.9],
  SG: [1.35, 103.8], ID: [-2.5, 118.0], PH: [12.9, 121.8], AU: [-25.3, 133.8],
  NZ: [-41.8, 172.5],
});

/** @returns {{lat:number,lon:number}|null} */
export function centroidOf(code) {
  const c = CENTROIDS[String(code || '').toUpperCase().slice(0, 2)];
  return c ? { lat: c[0], lon: c[1] } : null;
}

export { CENTROIDS };
