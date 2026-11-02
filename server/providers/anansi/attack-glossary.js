// Ananzi attack-map glossary: every alert and popup line comes in two voices.
//
//   plain      what it means, in everyday words
//   technical  the same thing in the jargon analysts and reports use
//
// Keep both short (one or two sentences). The research value is seeing the
// two side by side until the jargon becomes familiar.

/** blocklist.de services → arc colour + explanation. */
export const SERVICES = Object.freeze({
  ssh: {
    label: 'SSH break-in attempts',
    color: '#ff2b2b',
    plain: 'Bots guessing usernames and passwords to log into servers remotely and take them over.',
    technical: 'SSH brute force / credential stuffing against sshd (TCP/22).',
  },
  bruteforcelogin: {
    label: 'Website login guessing',
    color: '#ff5a4a',
    plain: 'Bots guessing passwords on website logins such as WordPress or Joomla admin pages.',
    technical: 'Web-application login brute force (wp-login.php, xmlrpc.php, /administrator).',
  },
  apache: {
    label: 'Website attacks',
    color: '#f4cf5e',
    plain: 'Probing websites for weak pages, leftover admin tools or known bugs to break in.',
    technical: 'HTTP attacks logged by web servers: path traversal, LFI/RFI, exploit probes, scanner signatures.',
  },
  mail: {
    label: 'Email server attacks',
    color: '#ff8a1f',
    plain: 'Trying to break into email servers or use them to send spam.',
    technical: 'SMTP abuse: AUTH brute force and open-relay probing (TCP/25, 465, 587).',
  },
  imap: {
    label: 'Mailbox break-ins',
    color: '#e8a33c',
    plain: 'Guessing passwords to get into people’s mailboxes.',
    technical: 'IMAP/POP3 authentication brute force (TCP/143, 993, 110, 995).',
  },
  ftp: {
    label: 'File-server break-ins',
    color: '#c9a227',
    plain: 'Guessing passwords on old-style file servers to steal or plant files.',
    technical: 'FTP brute force against TCP/21.',
  },
  sip: {
    label: 'Phone-system attacks',
    color: '#e0457b',
    plain: 'Attacking internet phone systems, usually to make fraudulent calls on someone else’s bill.',
    technical: 'SIP/VoIP scanning and REGISTER brute force (UDP/5060) for toll fraud.',
  },
  bots: {
    label: 'Spam bots',
    color: '#c04dd8',
    plain: 'Automated bots spamming sign-up forms, comments and forums.',
    technical: 'Registration/comment spam bots and RFI attempts.',
  },
});

export const SERVICE_ORDER = Object.freeze(['ssh', 'bruteforcelogin', 'apache', 'mail', 'imap', 'ftp', 'sip', 'bots']);

/** Ports: the "most targeted ports" readout. */
const PORTS = {
  22: ['remote logins (SSH)', 'SSH — remote shell; brute-force target'],
  23: ['old remote logins on cheap routers and cameras — the favourite target of IoT botnets like Mirai', 'Telnet — cleartext remote shell; IoT botnet propagation'],
  80: ['websites', 'HTTP — web servers and exploit probes'],
  443: ['secure websites', 'HTTPS — TLS web servers'],
  445: ['Windows file sharing — how WannaCry spread', 'SMB — Windows file sharing; EternalBlue-class exploits'],
  3389: ['Windows Remote Desktop — a top way ransomware gangs get in', 'RDP — remote desktop; credential brute force and BlueKeep-class exploits'],
  1433: ['Microsoft SQL databases', 'MSSQL — database brute force'],
  3306: ['MySQL databases', 'MySQL — database brute force'],
  5060: ['internet phone systems', 'SIP — VoIP signalling'],
  8080: ['web admin pages and proxies', 'HTTP-alt — admin panels, proxies'],
  2323: ['backup remote-login port on IoT gear', 'Telnet-alt — IoT botnets'],
  5555: ['Android debug access left open on TV boxes and phones', 'ADB — Android Debug Bridge exposed to the internet'],
  6379: ['Redis databases left open', 'Redis — unauthenticated database access'],
  25: ['email servers', 'SMTP — mail transfer'],
  53: ['internet address lookups (DNS)', 'DNS — amplification and resolver abuse'],
  123: ['clock-sync servers, abused to amplify DDoS floods', 'NTP — reflection/amplification'],
};
export function portExplained(port, service) {
  const p = PORTS[port];
  return p
    ? { plain: `Port ${port}: ${p[0]}.`, technical: `TCP/${port} ${p[1]}.` }
    : { plain: `Port ${port}${service ? ` (${service})` : ''}: a network door bots keep knocking on.`, technical: `Port ${port}${service ? ` — ${service}` : ''}.` };
}

/** ThreatFox threat types. */
export const THREAT_TYPES = Object.freeze({
  botnet_cc: {
    plain: 'A control server: infected computers phone home here to get their orders.',
    technical: 'Botnet C2 (command-and-control) endpoint.',
  },
  payload_delivery: {
    plain: 'A download point that hands out malware to victims.',
    technical: 'Payload delivery / dropper URL or host.',
  },
  payload: {
    plain: 'The malware file itself.',
    technical: 'Malware payload (file hash).',
  },
  cc_skimming: {
    plain: 'Code planted on shopping sites to steal card numbers at checkout.',
    technical: 'Web skimmer / Magecart C2.',
  },
});

/** Common malware families. Unknown families fall back to a generic line. */
const FAMILIES = {
  emotet: ['A “loader” that spreads by email and then installs other malware, often ransomware.', 'Loader / banking trojan; malspam-delivered'],
  qakbot: ['Email-spread malware that steals logins and opens the door for ransomware gangs.', 'QBot banking trojan / initial-access loader'],
  asyncrat: ['Gives a criminal full remote control of the victim’s PC: screen, files, keystrokes.', 'Open-source .NET RAT (remote access trojan)'],
  remcos: ['Remote-control malware sold as “admin software” and abused to spy on victims.', 'Commercial RAT abused for surveillance'],
  njrat: ['Old but popular remote-control malware for spying on PCs.', 'njRAT / Bladabindi .NET RAT'],
  xworm: ['Remote-control malware that also steals crypto wallets and passwords.', 'XWorm RAT / stealer'],
  dcrat: ['Cheap remote-control malware sold on criminal forums.', 'DarkCrystal RAT'],
  agenttesla: ['Records keystrokes and steals saved passwords from browsers and email apps.', 'AgentTesla .NET keylogger / infostealer'],
  formbook: ['Steals what you type into web forms, including passwords.', 'FormBook / XLoader form-grabbing infostealer'],
  redline: ['An “infostealer”: grabs saved passwords, cookies and crypto wallets in seconds.', 'RedLine infostealer (MaaS)'],
  lumma: ['An “infostealer” rented to criminals: steals passwords, cookies and crypto wallets.', 'Lumma (LummaC2) infostealer-as-a-service'],
  vidar: ['Steals browser passwords, cookies and crypto wallets.', 'Vidar infostealer'],
  stealc: ['Steals browser passwords, cookies and crypto wallets.', 'StealC infostealer'],
  'cobalt strike': ['A professional hacking tool for penetration testers that criminals pirate to control networks after breaking in.', 'Cobalt Strike Beacon C2 (post-exploitation framework)'],
  sliver: ['An open-source hacking toolkit used to control hacked machines.', 'Sliver C2 framework'],
  'brute ratel': ['A commercial hacking toolkit criminals use to control hacked machines quietly.', 'Brute Ratel C4 post-exploitation framework'],
  havoc: ['An open-source hacking toolkit used to control hacked machines.', 'Havoc C2 framework'],
  metasploit: ['A well-known hacking toolkit; here it is being used to control victims.', 'Metasploit / Meterpreter C2'],
  mirai: ['Infects routers and cameras with default passwords and turns them into a DDoS army.', 'Mirai IoT botnet'],
  gafgyt: ['Infects cheap routers and cameras to launch flood attacks.', 'Gafgyt / Bashlite IoT botnet'],
  mozi: ['Peer-to-peer botnet of hacked home routers.', 'Mozi P2P IoT botnet'],
  icedid: ['Banking malware that often leads to ransomware.', 'IcedID / BokBot loader'],
  pikabot: ['A loader that sneaks other malware onto PCs, a QakBot successor.', 'Pikabot loader'],
  darkgate: ['Malware-as-a-service that gives remote control and installs more malware.', 'DarkGate loader / RAT'],
  'netsupport rat': ['A real remote-support tool abused to secretly control victims’ PCs.', 'NetSupport Manager abused as RAT'],
  socgholish: ['Fake “update your browser” pop-ups on hacked sites that install malware.', 'SocGholish / FakeUpdates JS loader'],
  amadey: ['A small bot that installs other malware and steals data.', 'Amadey loader/bot'],
  smokeloader: ['A loader that downloads whatever malware its buyer wants.', 'SmokeLoader'],
};
export function familyExplained(name, threatType) {
  const key = String(name || '').trim().toLowerCase();
  const hit = FAMILIES[key] || Object.entries(FAMILIES).find(([k]) => key.includes(k))?.[1];
  const tt = THREAT_TYPES[threatType];
  if (hit) return { plain: hit[0], technical: `${hit[1]}${tt ? ` · ${tt.technical}` : ''}` };
  return {
    plain: tt ? tt.plain : 'Malicious software tracked by researchers.',
    technical: `${name || 'Unknown family'}${tt ? ` · ${tt.technical}` : ''}`,
  };
}

/** GreyNoise: "is this real?" */
export function greyNoiseExplained(g) {
  if (!g) return null;
  if (g.riot) {
    return {
      label: `Known service: ${g.name || 'business infrastructure'}`,
      plain: 'This is a well-known company’s server (like a cloud or security provider) — probably not an attacker.',
      technical: `GreyNoise RIOT: common business service${g.name ? ` (${g.name})` : ''}.`,
    };
  }
  if (g.noise && g.classification === 'benign') {
    return {
      label: 'Harmless scanner',
      plain: 'A known “good” scanner (search engine or security researcher) that checks the whole internet.',
      technical: `GreyNoise: noise=true, classification=benign${g.name ? ` (${g.name})` : ''}.`,
    };
  }
  if (g.noise && g.classification === 'malicious') {
    return {
      label: 'Mass attacker (background noise)',
      plain: 'It attacks everyone on the internet, not you specifically — like a burglar trying every door on every street.',
      technical: 'GreyNoise: noise=true, classification=malicious (opportunistic mass exploitation).',
    };
  }
  if (g.noise) {
    return {
      label: 'Mass scanner (intent unclear)',
      plain: 'It scans the whole internet; GreyNoise hasn’t decided if it’s good or bad.',
      technical: `GreyNoise: noise=true, classification=${g.classification || 'unknown'}.`,
    };
  }
  return {
    label: 'Not a mass scanner — possibly targeted',
    plain: 'GreyNoise does not see this address spraying the internet. If it is attacking, it may be picking its targets.',
    technical: 'GreyNoise: not observed as internet background noise (noise=false, riot=false).',
  };
}

export const FLAGS = Object.freeze({
  tor: {
    label: 'Via Tor',
    plain: 'Came through Tor, an anonymity network. The country shown is the Tor exit’s, not the real attacker’s.',
    technical: 'Source is a Tor exit relay (Tor Project bulk exit list); attribution unreliable.',
  },
  drop: {
    label: 'Criminal netblock',
    plain: 'This address sits in a block of internet addresses run by criminals or stolen from their owners. Nothing good comes from here.',
    technical: 'Listed on Spamhaus DROP (Don’t Route Or Peer) — hijacked or criminal-operated netblock.',
  },
  strong: {
    label: 'Repeat offender',
    plain: 'This address has been attacking for months, not just today.',
    technical: 'blocklist.de strongips: reported repeatedly over 2+ months.',
  },
});

export const DDOS = Object.freeze({
  L7: {
    label: 'Web DDoS',
    plain: 'Floods of fake web visits aimed at knocking a website offline.',
    technical: 'Layer 7 (HTTP) attack traffic mitigated by Cloudflare; share of mitigated requests.',
  },
  L3: {
    label: 'Network DDoS',
    plain: 'Floods of raw junk traffic meant to jam a network’s connection.',
    technical: 'Layer 3/4 volumetric DDoS (e.g. SYN/UDP floods) mitigated by Cloudflare.',
  },
});

/** CISA KEV entry → alert text. */
export function kevExplained(v) {
  const ransomware = String(v.knownRansomwareCampaignUse || '').toLowerCase() === 'known';
  return {
    title: `Hackers are using a ${v.vendorProject || ''} ${v.product || ''} bug right now`.replace(/\s+/g, ' ').trim(),
    plain: `Criminals are actively exploiting a flaw in ${v.vendorProject} ${v.product}${ransomware ? ', including ransomware gangs' : ''}. The US government has ordered its agencies to fix it${v.dueDate ? ` by ${v.dueDate}` : ''}.`,
    technical: `CISA KEV: ${v.cveID} — ${v.vulnerabilityName}. ${String(v.shortDescription || '').slice(0, 220)}${ransomware ? ' Known ransomware use.' : ''}`,
  };
}

/** Shadowserver honeypot exploited-vulnerability row → alert text. */
export function exploitedExplained(r) {
  const what = [r.vendor, r.product].filter(Boolean).join(' ');
  const kind = String(r.class || 'device').replace(/-/g, ' ');
  return {
    title: `Decoy servers caught attacks on ${what || kind}`,
    plain: `Shadowserver’s decoy servers (“honeypots”) saw attackers trying to break into ${what || 'a product'} — a ${kind}${r.iot === 'yes' ? ' (smart/IoT device)' : ''}.`,
    technical: `${r.vulnerability}${r.vulnerability_score ? ` (CVSS ${r.vulnerability_score}${r.vulnerability_severity ? ` ${r.vulnerability_severity}` : ''})` : ''} · ${r.type || 'scan'} · ${r['1d'] || r.connections || '?'} sources/day${r.cisa_kev === 'yes' ? ' · in CISA KEV' : ''}.`,
  };
}

/** OTX pulse → alert text. */
export function pulseExplained(p) {
  const fams = (p.malware_families || []).map((m) => (typeof m === 'string' ? m : m?.display_name || m?.id)).filter(Boolean);
  const industries = (p.industries || []).filter(Boolean);
  const countries = (p.targeted_countries || []).filter(Boolean);
  const parts = [
    p.adversary ? `the group “${p.adversary}”` : null,
    fams.length ? `malware ${fams.slice(0, 3).join(', ')}` : null,
  ].filter(Boolean);
  return {
    title: String(p.name || 'New threat report').slice(0, 140),
    plain: `Researchers shared a new report${parts.length ? ` about ${parts.join(' using ')}` : ''}${industries.length ? `, aimed at ${industries.slice(0, 3).join(', ')}` : ''}${countries.length ? ` in ${countries.slice(0, 3).join(', ')}` : ''}.`,
    technical: `OTX pulse${p.author_name ? ` by ${p.author_name}` : ''}: ${String(p.description || '').replace(/\s+/g, ' ').slice(0, 220) || 'IOCs and TTPs attached'}${(p.attack_ids || []).length ? ` · ATT&CK ${(p.attack_ids || []).slice(0, 4).map((a) => a?.id || a).join(', ')}` : ''}`,
  };
}

/** FortiGuard bulletins: we only have the headline, so explain the bulletin type. */
export const FORTIGUARD_KINDS = Object.freeze({
  'Outbreak Alert': {
    plain: 'Fortinet’s researchers are warning about an attack campaign that is spreading right now.',
    technical: 'FortiGuard Outbreak Alert: active exploitation / campaign advisory.',
  },
  'Threat Signal': {
    plain: 'Fortinet’s quick heads-up about a new threat worth knowing about.',
    technical: 'FortiGuard Threat Signal: emerging threat brief.',
  },
  PSIRT: {
    plain: 'A security fix announcement for Fortinet’s own products.',
    technical: 'FortiGuard PSIRT advisory (vendor vulnerability disclosure).',
  },
});
