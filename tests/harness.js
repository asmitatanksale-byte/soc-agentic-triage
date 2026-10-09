// Offline harness: runs the n8n Code-node logic in Node with a mock LLM, to test
// wiring, scoring and routing without n8n. NOT used for model results.
const fs = require('fs');
const wf = JSON.parse(fs.readFileSync(__dirname + '/../n8n/soc_triage_workflow.json'));
const cases = JSON.parse(fs.readFileSync(__dirname + '/../app/test_cases.json'));
const code = Object.fromEntries(wf.nodes.filter(n => n.type.endsWith('.code')).map(n => [n.name, n.parameters.jsCode]));

function mockLLM(req) {
  const sys = req.messages[0].content, ev = req.messages[1].content;
  const sev = (ev.match(/"severity":"(\w+)"/) || [])[1] || 'medium';
  const score = { low: 15, medium: 45, high: 70, critical: 95 }[sev];
  let out;
  if (sys.includes('Correlation Agent')) out = { is_campaign: /EV-\d+.*EV-\d+.*EV-\d+/.test(ev), related_event_ids: ev.match(/EV-\d+/g) || [], attack_stage: 'execution', pattern: 'mock', confidence: 0.8 };
  else if (sys.includes('Threat Intel Agent')) out = { ti_verdict: /malicious/.test(ev) ? 'malicious' : 'unknown', matched_indicators: [], threat_actor_or_family: 'unknown', mitre_techniques: ['T1486'], rationale: 'mock', confidence: 0.8 };
  else if (sys.includes('Asset & Identity')) out = { business_impact: 'medium', is_crown_jewel: /crown_jewel/.test(ev), privileged_identity: false, data_complete: !/NOT FOUND/.test(ev), context_notes: 'mock' };
  else if (sys.includes('Risk & Prioritisation')) out = { severity: sev, risk_score: score, escalate: score >= 70, false_positive_likelihood: 0.2, key_reasons: ['mock'], confidence: 0.8 };
  else out = { title: 'Mock incident', summary: 'mock summary', recommended_actions: [{ action: score >= 70 ? 'isolate_host' : 'monitor', type: score >= 70 ? 'containment' : 'investigation', requires_approval: false, reason: 'mock' }, { action: 'hack_back', type: 'containment', requires_approval: false, reason: 'test guardrail' }], open_questions: [] };
  return { choices: [{ message: { content: '<think>x</think>```json\n' + JSON.stringify(out) + '\n```' } }], usage: { total_tokens: 100 } };
}

function run(body) {
  const outputs = {};
  const $ = (name) => ({ first: () => { if (!(name in outputs)) throw new Error('not executed ' + name); return { json: outputs[name] }; } });
  const exec = (name, input) => {
    const fn = new Function('$', '$input', '$execution', code[name]);
    const res = fn($, { first: () => ({ json: input }) }, { resumeUrl: 'http://localhost:5678/webhook-waiting/123' });
    outputs[name] = res[0].json; return res[0].json;
  };
  let o = exec('SOC Orchestrator', { body });
  if (!o.valid) return { status: 'rejected', errors: o.errors };
  const pairs = [['SIEM Search (Tool)', 'Correlation Agent'], ['Threat Intel DB (Tool)', 'Threat Intel Agent'], ['CMDB & IAM (Tool)', 'Asset Context Agent'], ['Risk Evidence', 'Risk Agent'], ['Summary Evidence', 'Summary Agent']];
  for (const [tool, agent] of pairs) { const t = exec(tool, {}); outputs[agent] = mockLLM(t.llm_request); }
  const d = exec('Decision Engine', {});
  let c = d;
  if (d.route === 'auto_close') c = exec('A: Auto-Close', d);
  else {
    if (d.route === 'escalate') c = exec('E: Escalate Tier-2', d);
    if (d.route === 'exception') c = exec('X: Exception Queue', d);
    c = exec('H: Prepare Review', c);
    const ap = exec('Apply Analyst Decision', { body: { decision: 'approve', analyst_role: 'tier1', approved_actions: ['isolate_host', 'monitor'] } });
    c.apply = ap;
  }
  return c;
}

if (require.main !== module) { module.exports = { code, mockLLM }; return; }
for (const tc of cases) {
  const c = run({ alert: tc.alert, model: 'mock-model' });
  console.log(tc.case, tc.expected.route.padEnd(10), '->', String(c.route).padEnd(10), `rule=${c.rule_score} final=${c.final_score}`, c.flags?.join(','), '|', c.apply?.outcome || c.status, c.recommended_actions?.map(a => a.action + (a.allowed ? '' : '(BLOCKED)')).join(','));
}
console.log('invalid input ->', JSON.stringify(run({ alert: { alert_id: 'x' } })).slice(0, 120));
console.log('bad model ->', run({ alert: cases[0].alert, model: 'gpt-4' }).flags);
