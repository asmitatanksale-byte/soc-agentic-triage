// Mock n8n server for UI testing only (mock LLM). Mirrors the workflow's node logic.
const http = require('http');
const { code, mockLLM } = require('./harness.js');
const waiting = {};
const execNode = (outputs, name, input, resumeUrl) => {
  const $ = (n) => ({ first: () => { if (!(n in outputs)) throw new Error('nx'); return { json: outputs[n] }; } });
  const r = new Function('$', '$input', '$execution', code[name])($, { first: () => ({ json: input }) }, { resumeUrl });
  return (outputs[name] = r[0].json);
};
http.createServer((req, res) => {
  let b = ''; req.on('data', d => b += d); req.on('end', () => {
    const body = JSON.parse(b || '{}'); const send = (c, o) => { res.writeHead(c, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (req.url === '/webhook/soc-triage') {
      const id = Math.random().toString(36).slice(2), url = `http://localhost:5678/webhook-waiting/${id}`, out = {};
      const o = execNode(out, 'SOC Orchestrator', { body }, url);
      if (!o.valid) return send(400, { status: 'rejected_invalid_input', errors: o.errors, flags: o.flags });
      for (const [t, a] of [['SIEM Search (Tool)', 'Correlation Agent'], ['Threat Intel DB (Tool)', 'Threat Intel Agent'], ['CMDB & IAM (Tool)', 'Asset Context Agent'], ['Risk Evidence', 'Risk Agent'], ['Summary Evidence', 'Summary Agent']]) out[a] = mockLLM(execNode(out, t, {}, url).llm_request);
      let d = execNode(out, 'Decision Engine', {}, url);
      if (d.route === 'auto_close') return send(200, execNode(out, 'A: Auto-Close', d, url));
      if (d.route === 'escalate') d = execNode(out, 'E: Escalate Tier-2', d, url);
      if (d.route === 'exception') d = execNode(out, 'X: Exception Queue', d, url);
      d = execNode(out, 'H: Prepare Review', d, url); waiting[id] = out; return send(200, d);
    }
    const m = req.url.match(/webhook-waiting\/(\w+)/);
    if (m && waiting[m[1]]) return send(200, execNode(waiting[m[1]], 'Apply Analyst Decision', { body }, ''));
    send(404, { error: 'not found' });
  });
}).listen(5678, () => console.log('mock n8n on 5678'));
