import { c2intel } from './c2intel.js';
import { feodo, threatfox, urlhaus } from './abusech.js';
import { openphish, dshield } from './phishscan.js';
import { radar, greynoise, otx } from './keyed.js';
import { cymru, ripestat } from './enrichers.js';

export const FEEDS = [c2intel, feodo, threatfox, urlhaus, openphish, dshield, radar];   // polled
export const ANNOTATORS = [greynoise, otx];                                                // per-IP lookups when keyed
export const ENRICHERS = [cymru, ripestat];
export const ALL = [...FEEDS, ...ANNOTATORS, ...ENRICHERS];
export const adapterMap = () => new Map(ALL.map((a) => [a.name, a]));
export { c2intel, feodo, threatfox, urlhaus, openphish, dshield, radar, greynoise, otx, cymru, ripestat };
