// ===== TOOL: SIEM log search (mock, synthetic data) =====
// Pulls events for the same host / user from the last 24h and prepares the
// request for the Correlation Agent.
const o = $('SOC Orchestrator').first().json;
const a = o.alert_raw;

const SIEM_EVENTS = [
  { id: 'EV-1001', host: 'dev-web-02', user: null, ts: '-00:20', event: '412 failed SSH logins from 198.51.100.23 in 10 min' },
  { id: 'EV-1002', host: 'dev-web-02', user: null, ts: '-00:05', event: 'Firewall auto-blocked 198.51.100.23 (fail2ban rule)' },
  { id: 'EV-1003', host: 'dev-web-02', user: null, ts: '-00:01', event: 'No successful SSH logins recorded in last 24h' },
  { id: 'EV-2001', host: 'wks-mkt-14', user: 'r.iyer', ts: '-00:02', event: 'Proxy blocked request to ads-tracker.example (category: adware)' },
  { id: 'EV-3001', host: 'wks-hr-07', user: 'a.khan', ts: '-00:03', event: 'EDR quarantined test file, no process execution observed' },
  { id: 'EV-4001', host: 'lap-fin-22', user: 'j.mehta', ts: '-00:55', event: 'Login from 192.0.2.44 (Pune office) - success' },
  { id: 'EV-4002', host: 'lap-fin-22', user: 'j.mehta', ts: '-00:15', event: 'Login from 203.0.113.10 (Singapore) - success, MFA approved' },
  { id: 'EV-4003', host: 'lap-fin-22', user: 'j.mehta', ts: '-00:10', event: 'Accessed payroll export report (normal for role)' },
  { id: 'EV-5001', host: 'app-erp-01', user: 'adm.s.rao', ts: '-01:00', event: 'Change ticket CHG-4471 opened: ERP patching window 01:00-03:00' },
  { id: 'EV-5002', host: 'app-erp-01', user: 'adm.s.rao', ts: '-00:04', event: 'powershell.exe -EncodedCommand launched by adm.s.rao' },
  { id: 'EV-5003', host: 'app-erp-01', user: 'adm.s.rao', ts: '-00:03', event: 'Windows Update service restarted' },
  { id: 'EV-6001', host: 'unknown-host-77', user: null, ts: '-00:30', event: 'DHCP lease issued to unknown MAC on guest VLAN' },
  { id: 'EV-6002', host: 'unknown-host-77', user: null, ts: '-00:06', event: 'Beacon-like HTTPS every 60s to cdn-update-check.example' },
  { id: 'EV-7001', host: 'finance-db-01', user: 'svc-report', ts: '-00:08', event: 'SELECT * on customer_payments returned 182,000 rows' },
  { id: 'EV-7002', host: 'finance-db-01', user: 'svc-report', ts: '-00:07', event: 'Query issued from workstation wks-fin-09, not the reporting server' },
  { id: 'EV-8001', host: 'dc01', user: 'adm.k.patel', ts: '-00:40', event: 'adm.k.patel logged in via RDP from wks-it-03 at 02:10' },
  { id: 'EV-8002', host: 'dc01', user: 'adm.k.patel', ts: '-00:12', event: 'vssadmin delete shadows /all /quiet executed' },
  { id: 'EV-8003', host: 'dc01', user: 'adm.k.patel', ts: '-00:09', event: '14,500 files renamed with extension .nlock in 3 min' },
  { id: 'EV-8004', host: 'dc01', user: 'adm.k.patel', ts: '-00:08', event: 'Outbound TLS to 203.0.113.66:443' },
  { id: 'EV-8005', host: 'wks-it-03', user: 'adm.k.patel', ts: '-02:30', event: 'Mimikatz-like LSASS access detected (alert suppressed as duplicate)' },
  { id: 'EV-9001', host: 'fs-legal-01', user: 'svc-backup', ts: '-00:50', event: 'svc-backup interactive logon (normally non-interactive)' },
  { id: 'EV-9002', host: 'fs-legal-01', user: 'svc-backup', ts: '-00:20', event: '7z archive of \\\\legal\\contracts created (3.9 GB)' },
  { id: 'EV-9003', host: 'fs-legal-01', user: 'svc-backup', ts: '-00:10', event: 'HTTPS upload 4.2 GB to files-share-drop.example' },
  { id: 'EV-10001', host: 'm365-tenant', user: 'ceo.office', ts: '-01:10', event: '37 MFA push requests in 15 min from 198.51.100.77' },
  { id: 'EV-10002', host: 'm365-tenant', user: 'ceo.office', ts: '-01:02', event: 'MFA push approved, sign-in from 198.51.100.77' },
  { id: 'EV-10003', host: 'm365-tenant', user: 'ceo.office', ts: '-00:50', event: 'Inbox rule created: forward all to archive-mailbox.example' },
];

const related = SIEM_EVENTS
  .filter(e => e.host === a.host || (a.user && e.user === a.user))
  .map(e => ({ ...e, user: e.user ? (Object.keys(o.user_map).find(k => o.user_map[k] === e.user) || 'other-user') : null }));

const evidence = { alert: o.alert, related_events: related };

return [{
  json: {
    related_events: related,
    llm_request: {
      model: o.llm_model,
      ...o.llm_extra,
      temperature: 0,
      max_tokens: 800,
      messages: [
        { role: 'system', content: o.prompts.correlation },
        { role: 'user', content: 'EVIDENCE:\n' + JSON.stringify(evidence) },
      ],
    },
  },
}];
