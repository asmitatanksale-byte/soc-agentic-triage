// ===== TOOL: Threat-intel lookup (mock internal TI database, synthetic) =====
const o = $('SOC Orchestrator').first().json;
const a = o.alert_raw;

const TI_DB = {
  '198.51.100.23': { type: 'ip', reputation: 'benign', category: 'known internet scanner', note: 'Mass-scans SSH on the whole internet; no targeted activity' },
  'ads-tracker.example': { type: 'domain', reputation: 'suspicious', category: 'adware / tracking', note: 'Low-risk adware network' },
  '44d88612fea8a8f36de82e1278abb02f': { type: 'md5', reputation: 'benign', category: 'AV test file', note: 'EICAR anti-virus test file' },
  '203.0.113.10': { type: 'ip', reputation: 'benign', category: 'corporate VPN egress (Singapore PoP)', note: 'Owned by company VPN provider' },
  '192.0.2.44': { type: 'ip', reputation: 'benign', category: 'corporate office (Pune)', note: 'Company office NAT' },
  '203.0.113.66': { type: 'ip', reputation: 'malicious', category: 'ransomware C2', family: 'NightLock (fictional)', note: 'Seen in 4 partner-shared ransomware incidents this month' },
  'files-share-drop.example': { type: 'domain', reputation: 'suspicious', category: 'newly registered file-sharing', note: 'Registered 6 days ago; no business use seen' },
  'archive-mailbox.example': { type: 'domain', reputation: 'malicious', category: 'BEC infrastructure', note: 'Used in business-email-compromise forwarding rules' },
  '198.51.100.77': { type: 'ip', reputation: 'malicious', category: 'password-spray / MFA-fatigue botnet', note: 'Active MFA fatigue campaign' },
};

// Indicator extraction from structured fields + free text
const text = JSON.stringify(a);
const ips = text.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || [];
const domains = (text.match(/\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:example|com|net|org|io|ru|xyz)\b/gi) || []).map(d => d.toLowerCase());
const hashes = text.match(/\b[a-f0-9]{32}\b|\b[a-f0-9]{64}\b/gi) || [];
const indicators = [...new Set([...ips, ...domains, ...hashes])];

const matches = indicators.map(i => ({ indicator: i, ...(TI_DB[i] || { reputation: 'unknown', category: 'no record in TI database' }) }));
const rank = { malicious: 3, suspicious: 2, unknown: 1, benign: 0 };
const worst = matches.reduce((w, m) => (rank[m.reputation] > rank[w] ? m.reputation : w), matches.length ? 'benign' : 'unknown');

return [{
  json: {
    indicators,
    ti_matches: matches,
    ti_worst: worst,
    llm_request: {
      model: o.llm_model,
      ...o.llm_extra,
      temperature: 0,
      max_tokens: 800,
      messages: [
        { role: 'system', content: o.prompts.threat_intel },
        { role: 'user', content: 'EVIDENCE:\n' + JSON.stringify({ alert: o.alert, ti_matches: matches }) },
      ],
    },
  },
}];
