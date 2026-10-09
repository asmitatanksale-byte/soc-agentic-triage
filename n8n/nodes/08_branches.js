//@@ AUTO_CLOSE
// ===== A: Autonomous close (low risk, no containment) =====
const c = $input.first().json;
return [{ json: { ...c, status: 'closed_auto', hitl_required: false,
  audit: { event: 'auto_closed', by: 'agent', at: new Date().toISOString(), note: 'Low risk; closed autonomously with full evidence logged. Sample reviewed weekly by Tier-2 (quality control).' } } }];

//@@ ESCALATE
// ===== E: Escalation to Tier-2 / Incident Response (simulated notification) =====
const c = $input.first().json;
const sev = c.final_score >= 85 ? 'P1' : 'P2';
return [{ json: { ...c, status: 'escalated_awaiting_tier2', priority: sev, hitl_required: true, required_role: 'tier2',
  notification: { channel: 'SIMULATED: IR on-call page + #soc-incidents', sla_minutes: sev === 'P1' ? 15 : 60, message: `[${sev}] ${c.title} (${c.alert_id}) score ${c.final_score}` } } }];

//@@ EXCEPTION
// ===== Exception queue: incomplete data / injection / bad model output =====
const c = $input.first().json;
return [{ json: { ...c, status: 'exception_manual_review', priority: 'P3', hitl_required: true, required_role: 'tier1',
  exception: { reasons: c.route_reasons, handling: 'No automated action allowed. Analyst must verify evidence manually.' } } }];

//@@ PREP_HITL
// ===== Prepare the Human-in-the-Loop request =====
const c = $input.first().json;
return [{ json: { ...c,
  status: c.status || 'awaiting_analyst', priority: c.priority || 'P3',
  hitl_required: true, required_role: c.required_role || 'tier1',
  resume_url: $execution.resumeUrl,
  hitl_options: ['approve', 'reject', 'escalate'] } }];

//@@ APPLY_DECISION
// ===== Apply the SOC analyst's decision (all actions SIMULATED in the PoC) =====
const c = $('H: Prepare Review').first().json;
const b = $input.first().json.body || {};
const decision = b.decision || 'timeout';
const role = b.analyst_role || 'tier1';
const approved = Array.isArray(b.approved_actions) ? b.approved_actions : [];
const log = [];
let outcome;

// Access control guardrail: escalated (P1/P2) cases can only be approved by Tier-2
if (c.required_role === 'tier2' && role !== 'tier2' && decision === 'approve') {
  outcome = 'denied_insufficient_role';
  log.push('Approval rejected: escalated case requires a Tier-2 / IR lead.');
} else if (decision === 'approve') {
  outcome = 'approved';
  for (const a of c.recommended_actions.filter(x => x.allowed && approved.includes(x.action))) {
    log.push(`SIMULATED ${a.action}: request sent to ${a.type === 'containment' ? 'EDR/IAM/Firewall API' : 'ticketing'} for ${c.alert_id}`);
  }
  if (!log.length) log.push('Approved with no actions selected - ticket opened for follow-up.');
} else if (decision === 'reject') {
  outcome = 'closed_false_positive';
  log.push('Analyst closed case as false positive; feedback stored for tuning.');
} else if (decision === 'escalate') {
  outcome = 'escalated_by_analyst';
  log.push('SIMULATED: case handed to Tier-2 / IR with full agent trace.');
} else {
  outcome = 'sla_timeout_escalated';
  log.push('No analyst response within SLA - auto-escalated to Tier-2. No containment executed.');
}

return [{ json: {
  case_id: c.case_id, alert_id: c.alert_id, route: c.route, outcome,
  decided_by: b.analyst || 'system', analyst_role: role, comment: b.comment || '',
  approved_actions: approved, action_log: log, decided_at: new Date().toISOString(),
} }];
