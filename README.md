# Governed Agentic SOC Alert Triage — PoC (n8n + Streamlit)

```
Streamlit UI ──POST──▶ n8n Webhook ─▶ SOC Orchestrator (guardrails) ─▶ Input Valid?
   ▲                                     │
   │                                     ▼
   │     Correlation Tool ─▶ Alert Correlation Agent (LLM)
   │     Threat-Intel Tool ─▶ Threat Intelligence Agent (LLM)
   │     CMDB/IAM Tool    ─▶ Asset Context Agent (LLM)
   │     Risk Evidence Pack ─▶ Risk Prioritisation Agent (LLM)
   │     Summary Evidence Pack ─▶ Incident Summary Agent (LLM)
   │                                     ▼
   │             Decision Engine (rule score + LLM score + guardrails)
   │                                     ▼
   │     Route Case:  A auto-close | H analyst review | E escalate | Exception queue
   │                                     ▼
   └──── Respond (with resume URL) ─▶ H: Wait for analyst ─▶ Apply Analyst Decision
         UI Approve / Reject / Escalate ──POST resume URL──┘
```

All data is synthetic. Every containment action is **simulated**. No real systems are touched.

---

## 1. Run n8n (≈3 min)

```bash
docker run -it --rm --name n8n -p 5678:5678 \
  -e WEBHOOK_URL=http://localhost:5678/ \
  -v n8n_data:/home/node/.n8n docker.n8n.io/n8nio/n8n
```
(If you don't have Docker: `npx n8n`.) Open http://localhost:5678 and create the owner account.

## 2. Import the workflow (≈5 min)

1. **Workflows → Import from File →** `n8n/soc_triage_workflow.json`
2. **Create the LLM credential:** Credentials → New → **Header Auth**
   - Name: `Authorization`
   - Value: `Bearer <YOUR_GROQ_KEY>` (free key from console.groq.com → API Keys)
3. Open each of the 5 **Agent** nodes (bottom row of section 2) and choose that credential. The nodes are: Correlation, Threat Intel, Asset Context, Risk and Summary Agent.
4. Open the **SOC Orchestrator** node and check the config at the top:
   - `GROQ_URL` / `OLLAMA_URL`: models starting with `ollama/` go to Ollama on your PC, everything else goes to Groq. Default `OLLAMA_URL` is localhost (n8n via `npx`). If n8n runs in Docker, change it to `http://host.docker.internal:11434/v1/chat/completions`.
   - `MODEL_ALLOWLIST`: free defaults are `openai/gpt-oss-120b` and `qwen/qwen3.8-27b` (Groq free tier) and `ollama/llama3.1:8b` (local). Keep the UI sidebar list in sync.
5. **Save**, then switch the workflow to **Active** (top right). The UI calls the production URL `/webhook/soc-triage`.
   - To use the *test* URL (`/webhook-test/soc-triage`), you must click "Execute workflow" before every call.

> API keys stay only in the n8n credential store. Never put them in the UI, the code or a screenshot.

## 3. Run the UI (≈2 min)

```bash
cd app
pip install -r requirements.txt
streamlit run app.py
```

## 4. Demo script (covers every Stage-3 criterion)

| # | Case | What it shows | Expected route |
|---|------|---------------|----------------|
| 1 | TC01 SSH brute force (blocked) | Normal case, autonomous close | **A** auto_close |
| 2 | TC04 Impossible travel / VPN | Ambiguous case → analyst approves `monitor` | **H** hitl |
| 3 | TC08 Ransomware on DC | High-risk → P1 escalation. As **tier1** the buttons are locked; switch to **tier2** → approve `isolate_host` (simulated) | **E** escalate |
| 4 | TC07 Prompt injection in alert | Injection removed and flagged → forced manual review | exception |
| 5 | TC06 Unknown host | Missing CMDB data → exception queue | exception |
| 6 | Custom alert with missing fields | Input guardrail rejects the alert (HTTP 400) | rejected |
| 7 | Model Benchmark tab | 3 models × 10 cases, metrics, charts, CSV | — |

After each case, open the n8n **Executions** tab to show the run path (the green nodes) for your screenshots.

## 5. Model comparison

In the **Model Benchmark** tab:

1. Pick 3+ models (free set: gpt-oss-120b, Qwen 3.8 27B, Llama 3.1 8B via Ollama) and all 10 cases, then run. On the free tier, run one model at a time with the 30 s pause.
2. Every run uses the same prompts, evidence, JSON schema and temperature 0.
3. Score `explanation_quality` (1–5) in the table using the rubric.
4. Download `model_metrics.csv` and `benchmark_scored.csv`.

The metrics are: task completion, severity accuracy (exact and within one level), route accuracy, escalation precision and recall, false-positive rate, hallucination rate (entities not in the evidence), schema compliance, strict JSON (JSON-only after removing `<think>` blocks and code fences), latency, tokens and explanation quality.

Benchmark runs set `benchmark: true`, so the workflow ends after responding instead of waiting for a human.

## 6. Where each guardrail lives

See the **Guardrails** tab in the UI. In short:

| Guardrail | Where it lives |
|---|---|
| Input validation, prompt-injection filter, PII redaction, user pseudonymisation, model allowlist | Orchestrator node |
| Schema checks, hallucination check, playbook allowlist, "containment always needs approval", thresholds | Decision Engine node |
| Human-in-the-loop pause with a 60-minute SLA timeout that auto-escalates | Wait node |
| Tier-2-only approval for escalated cases | Apply Decision node (and the UI) |
| LLM retry ×2, with failures sent to the exception route | Agent nodes |
| Audit trail | `app/audit_log.jsonl` and n8n execution history |

## 7. Troubleshooting

| Symptom | Fix |
|---|---|
| UI: "Could not reach n8n" / 404 | Workflow not **Active**, or wrong URL in the sidebar |
| All routes = exception, flags `agent_failed:*` | Credential not selected on the agent nodes, or invalid model ID. Open the execution and look at the agent node output |
| HTTP 429 / `agent_failed` during benchmark | Groq free-tier limit (about 8K tokens/min per model). Raise the pause, run one model at a time |
| Ollama calls fail from n8n | Ollama not running, model not pulled, or wrong `OLLAMA_URL` (Docker needs `host.docker.internal`) |
| Approve button does nothing / 404 | Resume URLs are single-use. Run the triage again |
| Resume URL points to the wrong host | Set `WEBHOOK_URL` when starting n8n |

## 8. Offline rehearsal (no n8n, no API key)

`node tests/mock_n8n.js` starts a **mock** server on port 5678. It runs the same node code with a fake LLM, so you can rehearse the UI flow. Run `node tests/harness.js` for a quick routing check.

**Never present mock results as model results.**

## Files

- `n8n/soc_triage_workflow.json`: the workflow to import (31 nodes, including sticky notes with A/H/E labels)
- `n8n/nodes/*.js`: readable source of every Code node. `build_workflow.py` regenerates the JSON
- `app/app.py`: the Streamlit UI (triage console, HITL, audit log, benchmark, guardrails)
- `app/test_cases.json`: 10 synthetic test cases with ground truth (3 normal, 2 ambiguous, 2 exception, 3 high-risk)
