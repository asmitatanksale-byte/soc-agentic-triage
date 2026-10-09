// ===== Evidence pack for the Summary Agent =====
const o = $('SOC Orchestrator').first().json;
const pick = (n) => { const r = agentOut(n); return r.ok ? r.data : { unavailable: r.error }; };

const evidence = {
  alert: o.alert,
  related_events: $('SIEM Search (Tool)').first().json.related_events,
  correlation_agent: pick('Correlation Agent'),
  threat_intel_agent: pick('Threat Intel Agent'),
  asset_agent: pick('Asset Context Agent'),
  risk_agent: pick('Risk Agent'),
};

return [{
  json: {
    llm_request: {
      model: o.llm_model,
      ...o.llm_extra,
      temperature: 0,
      max_tokens: 1000,
      messages: [
        { role: 'system', content: o.prompts.summary },
        { role: 'user', content: 'EVIDENCE:\n' + JSON.stringify(evidence) },
      ],
    },
  },
}];
