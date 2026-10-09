// ===== DECISION ENGINE: deterministic scoring + guardrails + routing =====
// The LLM never decides alone: final score = 50% rule-based + 50% LLM risk score,
// and hard guardrails can override the route to HITL / exception.
const o = $('SOC Orchestrator').first().json;
const a = o.alert_raw;
const tiTool = $('Threat Intel DB (Tool)').first().json;
const assetTool = $('CMDB & IAM (Tool)').first().json;
const corrTool = $('SIEM Search (Tool)').first().json;

const agents = {
  correlation: agentOut('Correlation Agent'),
  threat_intel: agentOut('Threat Intel Agent'),
  asset_context: agentOut('Asset Context Agent'),
  risk: agentOut('Risk Agent'),
  summary: agentOut('Summary Agent'),
};
const reasons = [];
const flags = [...o.flags];

// ---- 1. Rule-based score (transparent, auditable) ----
const sevBase = { low: 10, medium: 25, high: 40, critical: 50 }[String(a.severity).toLowerCase()] ?? 25;
const critPts = { low: 0, medium: 10, high: 20, crown_jewel: 30 }[assetTool.asset?.criticality] ?? 10;
const tiPts = { malicious: 25, suspicious: 10, unknown: 0, benign: -10 }[tiTool.ti_worst] ?? 0;
const privPts = assetTool.identity?.privileged ? 10 : 0;
const corrPts = corrTool.related_events.length >= 3 ? 10 : 0;
const txt = JSON.stringify(a).toLowerCase();
const containedPts = /(blocked|quarantined|auto-blocked)/.test(txt) ? -15 : 0;
const changePts = /chg-\d+|change ticket|maintenance window/.test(txt + JSON.stringify(corrTool.related_events).toLowerCase()) ? -20 : 0;
const typePts = { impossible_travel: 10, data_exfiltration: 10, ransomware_behaviour: 10, mail_forwarding_rule: 10, beaconing: 5 }[a.type] ?? 0;
const rule_score = Math.max(0, Math.min(100, sevBase + critPts + tiPts + privPts + corrPts + containedPts + changePts + typePts));
const rule_breakdown = { severity: sevBase, asset_criticality: critPts, threat_intel: tiPts, privileged_identity: privPts, correlation: corrPts, already_contained: containedPts, change_ticket: changePts, alert_type: typePts };

// ---- 2. Blend with the LLM risk score ----
const r = agents.risk.ok ? agents.risk.data : null;
const llm_score = r && Number.isFinite(Number(r.risk_score)) ? Math.max(0, Math.min(100, Number(r.risk_score))) : null;
const final_score = llm_score === null ? rule_score : Math.round(0.5 * rule_score + 0.5 * llm_score);
const confidence = r && Number.isFinite(Number(r.confidence)) ? Number(r.confidence) : 0;

// ---- 3. Structured-output compliance ----
const REQUIRED = {
  correlation: ['is_campaign', 'attack_stage', 'confidence'],
  threat_intel: ['ti_verdict', 'mitre_techniques', 'confidence'],
  asset_context: ['business_impact', 'is_crown_jewel', 'data_complete'],
  risk: ['severity', 'risk_score', 'escalate', 'confidence'],
  summary: ['title', 'summary', 'recommended_actions'],
};
const schema = {};
for (const [k, v] of Object.entries(agents)) {
  schema[k] = v.ok && REQUIRED[k].every(f => v.data[f] !== undefined);
  if (!v.ok) flags.push(`agent_failed:${k}`);
  else if (!schema[k]) flags.push(`schema_violation:${k}`);
}
const schema_compliance = Object.values(schema).filter(Boolean).length / 5;

// ---- 4. Hallucination check: entities in LLM output that are NOT in the evidence ----
const evidenceText = JSON.stringify([a, o.alert, corrTool.related_events, tiTool.ti_matches, assetTool.asset, assetTool.identity]).toLowerCase();
const llmText = Object.values(agents).filter(x => x.ok).map(x => JSON.stringify(x.data)).join(' ');
const ents = new Set([
  ...(llmText.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || []),
  ...(llmText.match(/\bEV-\d+\b/g) || []),
  ...(llmText.match(/\bCVE-\d{4}-\d+\b/gi) || []),
  ...(llmText.match(/\b[a-f0-9]{32,64}\b/gi) || []),
  ...(llmText.match(/\b[a-z0-9-]+\.(?:example|com|net|org|io|ru|xyz)\b/gi) || []),
]);
const hallucinated = [...ents].filter(e => !evidenceText.includes(e.toLowerCase()));
const badMitre = (agents.threat_intel.data?.mitre_techniques || []).filter(t => !/^T\d{4}(\.\d{3})?$/.test(String(t).split(/[\s:-]/)[0]));
if (hallucinated.length) flags.push('hallucinated_entities');
if (badMitre.length) flags.push('invalid_mitre_ids');

// ---- 5. Action guardrail: containment ALWAYS needs human approval ----
const PLAYBOOK = ['isolate_host', 'disable_account', 'reset_credentials', 'block_ip', 'block_domain', 'remove_mail_rule', 'collect_forensics', 'open_ticket', 'notify_asset_owner', 'monitor', 'close_as_false_positive'];
const CONTAINMENT = ['isolate_host', 'disable_account', 'reset_credentials', 'block_ip', 'block_domain', 'remove_mail_rule'];
const actions = (agents.summary.data?.recommended_actions || []).map(x => {
  const act = String(x.action || '').toLowerCase().trim();
  const allowed = PLAYBOOK.includes(act);
  const containment = CONTAINMENT.includes(act);
  return { ...x, action: act, allowed, requires_approval: containment ? true : !!x.requires_approval, guardrail_note: !allowed ? 'BLOCKED: not in playbook' : (containment ? 'Containment: human approval enforced' : '') };
});
if (actions.some(x => !x.allowed)) flags.push('non_playbook_action_blocked');
const hasContainment = actions.some(x => x.allowed && CONTAINMENT.includes(x.action));

// ---- 6. Routing ----
let route;
const isCrownMal = assetTool.asset?.criticality === 'crown_jewel' && tiTool.ti_worst === 'malicious';
if (o.injection_detected) { route = 'exception'; reasons.push('Prompt-injection text found in alert - forced human review'); }
else if (!assetTool.asset_found) { route = 'exception'; reasons.push('Asset not found in CMDB - context incomplete'); }
else if (!agents.risk.ok) { route = 'exception'; reasons.push('Risk agent output unusable - ' + agents.risk.error); }
else if (confidence < 0.5) { route = 'exception'; reasons.push(`Low model confidence (${confidence})`); }
else if (final_score >= 70 || isCrownMal) { route = 'escalate'; reasons.push(isCrownMal ? 'Crown-jewel asset + malicious TI' : `Final score ${final_score} >= 70`); }
else if (final_score >= 40) { route = 'hitl'; reasons.push(`Final score ${final_score} in 40-69 band - analyst decision needed`); }
else if (hasContainment && final_score >= 25) { route = 'hitl'; reasons.push('Low score but containment proposed - analyst approval needed'); }
else if (hasContainment) { route = 'auto_close'; reasons.push(`Final score ${final_score} < 25 - proposed containment logged but NOT executed`); }
else { route = 'auto_close'; reasons.push(`Final score ${final_score} < 40, no containment needed`); }
if (route === 'auto_close' && (hallucinated.length || schema_compliance < 1)) { route = 'hitl'; reasons.push('Output quality issue (hallucination/schema) - auto-close blocked'); }

const now = Date.now();
return [{
  json: {
    case_id: o.case_id,
    alert_id: a.alert_id,
    model: o.model,
    benchmark: o.benchmark,
    route,
    route_reasons: reasons,
    rule_score, rule_breakdown, llm_score, final_score, confidence,
    llm_severity: r?.severity ?? null,
    llm_escalate: r?.escalate ?? null,
    false_positive_likelihood: r?.false_positive_likelihood ?? null,
    schema_compliance, schema_by_agent: schema,
    strict_json: Object.values(agents).filter(x => x.ok && x.strict).length / 5,
    hallucinated_entities: hallucinated, invalid_mitre: badMitre,
    flags: [...new Set(flags)],
    recommended_actions: actions,
    title: agents.summary.data?.title ?? `Alert ${a.alert_id}`,
    summary: agents.summary.data?.summary ?? 'Summary unavailable - see agent trace.',
    open_questions: agents.summary.data?.open_questions ?? [],
    agent_trace: Object.fromEntries(Object.entries(agents).map(([k, v]) => [k, v.ok ? v.data : { error: v.error, raw: String(v.raw).slice(0, 500) }])),
    tool_results: { related_events: corrTool.related_events, ti_matches: tiTool.ti_matches, asset: assetTool.asset, identity: assetTool.identity },
    user_map: o.user_map,
    tokens: Object.values(agents).reduce((s, x) => s + (x.usage?.total_tokens || 0), 0),
    latency_ms: now - o.started_at,
    decided_at: new Date(now).toISOString(),
  },
}];
