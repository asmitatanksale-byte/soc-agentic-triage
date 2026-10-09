// ===== TOOL: CMDB + IAM lookup (mock, synthetic) =====
const o = $('SOC Orchestrator').first().json;
const a = o.alert_raw;

const CMDB = {
  'dev-web-02':    { criticality: 'low',         env: 'dev',  owner_team: 'Web Platform', data: 'none',               internet_facing: true },
  'wks-mkt-14':    { criticality: 'low',         env: 'prod', owner_team: 'Marketing',    data: 'internal',           internet_facing: false },
  'wks-hr-07':     { criticality: 'medium',      env: 'prod', owner_team: 'HR',           data: 'employee PII',       internet_facing: false },
  'lap-fin-22':    { criticality: 'medium',      env: 'prod', owner_team: 'Finance',      data: 'payroll reports',    internet_facing: false },
  'app-erp-01':    { criticality: 'high',        env: 'prod', owner_team: 'ERP',          data: 'financial records',  internet_facing: false },
  'finance-db-01': { criticality: 'crown_jewel', env: 'prod', owner_team: 'Finance IT',   data: 'customer payment data', internet_facing: false },
  'dc01':          { criticality: 'crown_jewel', env: 'prod', owner_team: 'Identity',     data: 'Active Directory',   internet_facing: false },
  'fs-legal-01':   { criticality: 'crown_jewel', env: 'prod', owner_team: 'Legal',        data: 'contracts, M&A',     internet_facing: false },
  'm365-tenant':   { criticality: 'high',        env: 'prod', owner_team: 'Collaboration', data: 'executive email',   internet_facing: true },
};
const IAM = {
  'r.iyer':      { dept: 'Marketing', privileged: false, account_type: 'human' },
  'a.khan':      { dept: 'HR',        privileged: false, account_type: 'human' },
  'j.mehta':     { dept: 'Finance',   privileged: false, account_type: 'human', note: 'No travel request on file; VPN user' },
  'adm.s.rao':   { dept: 'ERP Ops',   privileged: true,  account_type: 'admin' },
  'svc-report':  { dept: 'Finance IT', privileged: false, account_type: 'service', note: 'Should only run from rpt-srv-01' },
  'adm.k.patel': { dept: 'IT',        privileged: true,  account_type: 'domain admin' },
  'svc-backup':  { dept: 'IT',        privileged: true,  account_type: 'service', note: 'Non-interactive backup account' },
  'ceo.office':  { dept: 'Executive', privileged: true,  account_type: 'VIP human' },
};

const asset = CMDB[a.host] || null;
const identity = a.user ? (IAM[a.user] || null) : null;
const evidence = {
  alert: o.alert,
  asset_record: asset || 'NOT FOUND IN CMDB',
  identity_record: a.user ? (identity || 'NOT FOUND IN IAM') : 'no user in alert',
};

return [{
  json: {
    asset,
    identity,
    asset_found: !!asset,
    llm_request: {
      model: o.llm_model,
      ...o.llm_extra,
      temperature: 0,
      max_tokens: 800,
      messages: [
        { role: 'system', content: o.prompts.asset },
        { role: 'user', content: 'EVIDENCE:\n' + JSON.stringify(evidence) },
      ],
    },
  },
}];
