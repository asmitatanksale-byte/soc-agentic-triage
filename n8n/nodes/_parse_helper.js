// --- helper: robustly read an LLM agent's JSON output ---
function agentOut(nodeName) {
  let resp;
  try { resp = $(nodeName).first().json; } catch (e) { return { ok: false, error: 'node not executed', data: null, raw: '' }; }
  if (resp.error) return { ok: false, error: 'LLM call failed: ' + JSON.stringify(resp.error).slice(0, 200), data: null, raw: '' };
  const raw = resp?.choices?.[0]?.message?.content ?? '';
  let txt = String(raw).replace(/<think>[\s\S]*?<\/think>/gi, '').replace(/```json|```/gi, '').trim();
  const s = txt.indexOf('{'), e = txt.lastIndexOf('}');
  if (s === -1 || e === -1) return { ok: false, error: 'no JSON object in output', data: null, raw };
  try { return { ok: true, strict: s === 0 && e === txt.length - 1, data: JSON.parse(txt.slice(s, e + 1)), raw, usage: resp.usage || null }; }
  catch (err) { return { ok: false, error: 'invalid JSON: ' + err.message, data: null, raw }; }
}
