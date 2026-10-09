// ===== Evidence pack for the Risk / Prioritisation Agent =====
const o = $('SOC Orchestrator').first().json;
const corr = agentOut('Correlation Agent');
const ti = agentOut('Threat Intel Agent');
const asset = agentOut('Asset Context Agent');

const evidence = {
  alert: o.alert,
  correlation_agent: corr.ok ? corr.data : { unavailable: corr.error },
  threat_intel_agent: ti.ok ? ti.data : { unavailable: ti.error },
  threat_intel_records: $('Threat Intel DB (Tool)').first().json.ti_matches,
  asset_agent: asset.ok ? asset.data : { unavailable: asset.error },
  asset_record: $('CMDB & IAM (Tool)').first().json.asset || 'NOT FOUND IN CMDB',
};

return [{
  json: {
    llm_request: {
      model: o.llm_model,
      ...o.llm_extra,
      temperature: 0,
      max_tokens: 800,
      messages: [
        { role: 'system', content: o.prompts.risk },
        { role: 'user', content: 'EVIDENCE:\n' + JSON.stringify(evidence) },
      ],
    },
  },
}];
