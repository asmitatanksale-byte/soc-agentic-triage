"""SOC Agentic Triage - analyst console (Streamlit UI for the n8n workflow).

Run:  streamlit run app.py
"""
import json, os, time, datetime as dt, pathlib
import pandas as pd
import requests
import streamlit as st

HERE = pathlib.Path(__file__).parent
CASES = json.loads((HERE / "test_cases.json").read_text())
AUDIT = HERE / "audit_log.jsonl"
RESULTS = HERE / "results"
RESULTS.mkdir(exist_ok=True)

# Free setup: Groq free tier + Ollama on your PC ("ollama/" prefix, local only)
DEFAULT_MODELS = [
    "openai/gpt-oss-120b",
    "qwen/qwen3.8-27b",
    "ollama/gemma3:4b",
    "openai/gpt-oss-20b",
    "ollama/llama3.1:8b",
]


def cfg(key, default=None):
    """Settings from Streamlit secrets (cloud) or environment variables, else default (local)."""
    try:
        if key in st.secrets:
            return st.secrets[key]
    except Exception:
        pass
    return os.environ.get(key, default)


WEBHOOK_DEFAULT = cfg("N8N_WEBHOOK_URL", "http://localhost:5678/webhook/soc-triage")
_m = cfg("MODELS")
MODELS_DEFAULT = ([x.strip() for x in _m.split(",") if x.strip()] if isinstance(_m, str) else list(_m)) if _m else DEFAULT_MODELS
APP_PASSWORD = cfg("APP_PASSWORD")
CLOUD = "localhost" not in WEBHOOK_DEFAULT and "127.0.0.1" not in WEBHOOK_DEFAULT
ROUTE_STYLE = {
    "auto_close": ("A - Autonomous close", "#1f9d55"),
    "hitl": ("H - Analyst review required", "#d97706"),
    "escalate": ("E - Escalated to Tier-2 / IR", "#dc2626"),
    "exception": ("Exception - manual queue", "#7c3aed"),
}

st.set_page_config(page_title="SOC Agentic Triage", page_icon="🛡️", layout="wide")


# ---------------- helpers ----------------
def audit(event: dict):
    event = {"ts": dt.datetime.now().isoformat(timespec="seconds"), **event}
    with AUDIT.open("a") as f:
        f.write(json.dumps(event) + "\n")


def call_workflow(url, alert, model, analyst, benchmark=False, timeout=900, wake_retries=6):
    """POST the alert to n8n. If the free cloud host is asleep/starting (HTML or 5xx), wait and retry."""
    t0 = time.time()
    for attempt in range(wake_retries + 1):
        try:
            r = requests.post(url, json={"alert": alert, "model": model, "analyst": analyst, "benchmark": benchmark}, timeout=timeout)
        except requests.ConnectionError:
            if attempt == wake_retries:
                raise
            time.sleep(15)
            continue
        waking = r.status_code in (502, 503, 504) or "text/html" in r.headers.get("content-type", "")
        if not waking or attempt == wake_retries:
            break
        time.sleep(15)
    rt = int((time.time() - t0) * 1000)
    try:
        data = r.json()
    except Exception:
        data = {"status": "error", "http_status": r.status_code, "text": r.text[:500]}
    if isinstance(data, list):
        data = data[0] if data else {}
    data["_roundtrip_ms"] = rt
    data["_http_status"] = r.status_code
    return data


def badge(route):
    label, color = ROUTE_STYLE.get(route, (route or "unknown", "#6b7280"))
    st.markdown(f"<div style='background:{color};color:white;padding:10px 16px;border-radius:8px;"
                f"font-size:1.15rem;font-weight:600'>{label}</div>", unsafe_allow_html=True)


# ---------------- access gate (cloud) ----------------
if APP_PASSWORD and not st.session_state.get("authed"):
    st.title("🛡️ Governed Agentic SOC Alert Triage")
    pw = st.text_input("Access code", type="password")
    if st.button("Enter"):
        if pw == APP_PASSWORD:
            st.session_state["authed"] = True
            st.rerun()
        else:
            st.error("Wrong access code")
    st.stop()

# ---------------- sidebar ----------------
with st.sidebar:
    st.header("⚙️ Settings")
    webhook = st.text_input("n8n webhook URL", WEBHOOK_DEFAULT,
                            help="Use /webhook-test/soc-triage while the workflow is open in the n8n editor")
    analyst = st.text_input("Analyst name", "analyst.demo")
    role = st.selectbox("Analyst role (access control)", ["tier1", "tier2"],
                        help="Escalated cases can only be approved by Tier-2")
    models_txt = st.text_area("Approved models (one per line)", "\n".join(MODELS_DEFAULT), height=110,
                              help="Must also be in MODEL_ALLOWLIST in the n8n Orchestrator node")
    models = [m.strip() for m in models_txt.splitlines() if m.strip()]
    model = st.selectbox("Model for this run", models)
    st.caption("All data is synthetic. Containment actions are simulated.")
    if CLOUD:
        st.info("Hosted demo on free infrastructure: the first run after a quiet period can take ~1 minute "
                "while the workflow engine wakes up. Local-only (Ollama) models are benchmarked in the saved results.")

st.title("🛡️ Governed Agentic SOC Alert Triage")
st.caption("UI → n8n Orchestrator → Correlation · Threat Intel · Asset Context · Risk · Summary agents → "
           "Decision Engine → Auto-close / Human review / Escalation")

tab1, tab2, tab3, tab4 = st.tabs(["🚨 Triage Console", "📜 Audit Log", "📊 Model Benchmark", "🔒 Guardrails"])

# ================= TAB 1: triage console =================
with tab1:
    left, right = st.columns([1, 1.6])
    with left:
        st.subheader("1. Incoming alert")
        opts = [f"{c['case']} · {c['category']} · {c['name']}" for c in CASES] + ["Custom alert (paste JSON)"]
        pick = st.selectbox("Alert queue", opts)
        idx = opts.index(pick)
        default = json.dumps(CASES[idx]["alert"], indent=2) if idx < len(CASES) else json.dumps(
            {"alert_id": "ALT-X", "source": "", "type": "", "severity": "medium", "host": "", "timestamp": "", "description": ""}, indent=2)
        alert_txt = st.text_area("Alert JSON", default, height=330, key=f"alert_{idx}")
        if idx < len(CASES):
            st.caption(f"Expected (ground truth): {CASES[idx]['expected']}")
        if st.button("▶ Run agentic triage", type="primary", width="stretch"):
            try:
                alert = json.loads(alert_txt)
            except json.JSONDecodeError as e:
                st.error(f"Invalid JSON: {e}")
                st.stop()
            with st.spinner(f"n8n orchestrating 5 agents with {model}…"):
                try:
                    res = call_workflow(webhook, alert, model, analyst)
                except requests.RequestException as e:
                    st.error(f"Could not reach n8n: {e}")
                    st.stop()
            st.session_state["result"] = res
            st.session_state.pop("decision", None)
            audit({"event": "triage_run", "analyst": analyst, "model": model, "alert_id": alert.get("alert_id"),
                   "case_id": res.get("case_id"), "route": res.get("route"), "final_score": res.get("final_score"),
                   "flags": res.get("flags"), "status": res.get("status")})

    with right:
        res = st.session_state.get("result")
        if not res:
            st.info("Select an alert and run the triage. The workflow result, agent trace and approval panel appear here.")
        elif res.get("status") == "rejected_invalid_input" or res.get("_http_status", 200) >= 400:
            st.error("Input guardrail rejected the alert")
            st.json(res)
        else:
            st.subheader(f"2. {res.get('title', 'Result')}")
            badge(res.get("route"))
            st.write("")
            c = st.columns(5)
            c[0].metric("Final score", res.get("final_score"))
            c[1].metric("Rule score", res.get("rule_score"))
            c[2].metric("LLM score", res.get("llm_score"))
            c[3].metric("Confidence", res.get("confidence"))
            c[4].metric("Latency", f"{res.get('_roundtrip_ms', 0) / 1000:.1f}s")
            st.markdown(f"**Case** `{res.get('case_id')}` · **Priority** {res.get('priority', '-')} · "
                        f"**Status** `{res.get('status')}` · **Model** `{res.get('model')}`")
            st.markdown("**Why this route:** " + "; ".join(res.get("route_reasons", [])))
            if res.get("flags"):
                st.warning("Guardrail flags: " + ", ".join(res["flags"]))
            st.markdown("**Incident summary**")
            st.write(res.get("summary"))
            if res.get("open_questions"):
                st.markdown("**Open questions:** " + " · ".join(res["open_questions"]))
            if res.get("notification"):
                st.error(f"🚨 {res['notification']['channel']} — SLA {res['notification']['sla_minutes']} min: "
                         f"{res['notification']['message']}")

            with st.expander("🔎 Agent trace (multi-agent reasoning)", expanded=False):
                for name, out in (res.get("agent_trace") or {}).items():
                    ok = "error" not in out
                    st.markdown(f"**{'✅' if ok else '❌'} {name.replace('_', ' ').title()} Agent**")
                    st.json(out, expanded=False)
            with st.expander("🧰 Tool / data results (SIEM, Threat Intel, CMDB, IAM)"):
                st.json(res.get("tool_results", {}), expanded=False)
                if res.get("user_map"):
                    st.caption(f"Pseudonym map (never sent to the LLM): {res['user_map']}")
            with st.expander("🧮 Scoring breakdown & output-quality checks"):
                st.table(pd.DataFrame([res.get("rule_breakdown", {})]).T.rename(columns={0: "points"}))
                st.write({"schema_compliance": res.get("schema_compliance"), "schema_by_agent": res.get("schema_by_agent"),
                          "hallucinated_entities": res.get("hallucinated_entities"), "invalid_mitre": res.get("invalid_mitre"),
                          "tokens": res.get("tokens")})

            acts = res.get("recommended_actions", [])
            if acts:
                st.markdown("**3. Recommended actions**")
                st.dataframe(pd.DataFrame(acts), width="stretch", hide_index=True)

            # ---------- HITL panel ----------
            if res.get("resume_url"):
                st.markdown("---")
                st.subheader("4. 👤 Human-in-the-loop decision")
                need = res.get("required_role", "tier1")
                st.caption(f"Required role: **{need}** · You are: **{role}**. The workflow is paused in n8n until you decide.")
                allowed = [a["action"] for a in acts if a.get("allowed")]
                chosen = st.multiselect("Actions to approve", allowed,
                                        default=[a for a in allowed if a not in ("close_as_false_positive",)])
                comment = st.text_input("Analyst comment / justification")
                locked = need == "tier2" and role != "tier2"
                if locked:
                    st.warning("🔐 Access control: only a Tier-2 / IR lead can approve or close this escalated case. "
                               "Switch role in the sidebar (demo) or escalate.")
                b1, b2, b3 = st.columns(3)
                decision = None
                if b1.button("✅ Approve selected actions", width="stretch", disabled=locked):
                    decision = "approve"
                if b2.button("🚫 Reject - false positive", width="stretch", disabled=locked):
                    decision = "reject"
                if b3.button("⬆️ Escalate to Tier-2", width="stretch"):
                    decision = "escalate"
                if decision:
                    if not comment.strip():
                        st.error("A justification comment is required for every human decision (audit requirement).")
                    else:
                        try:
                            r = requests.post(res["resume_url"], json={"decision": decision, "analyst": analyst, "analyst_role": role,
                                                                      "comment": comment, "approved_actions": chosen}, timeout=60)
                            out = r.json() if r.headers.get("content-type", "").startswith("application/json") else {"response": r.text}
                        except requests.RequestException as e:
                            out = {"error": str(e)}
                        st.session_state["decision"] = out
                        audit({"event": "human_decision", "analyst": analyst, "role": role, "case_id": res.get("case_id"),
                               "decision": decision, "approved_actions": chosen, "comment": comment, "result": out})
                if st.session_state.get("decision"):
                    d = st.session_state["decision"]
                    d = d[0] if isinstance(d, list) and d else d
                    (st.error if "denied" in str(d.get("outcome", "")) else st.success)(f"Outcome: {d.get('outcome', d)}")
                    for line in d.get("action_log", []):
                        st.write("•", line)

# ================= TAB 2: audit log =================
with tab2:
    st.subheader("Audit trail (every run and every human decision)")
    if AUDIT.exists():
        rows = [json.loads(l) for l in AUDIT.read_text().splitlines() if l.strip()]
        df = pd.DataFrame(rows)
        st.dataframe(df.iloc[::-1], width="stretch", hide_index=True)
        st.download_button("Download audit log (CSV)", df.to_csv(index=False), "audit_log.csv")
    else:
        st.info("No events yet.")

# ================= TAB 3: benchmark =================
SEV = ["low", "medium", "high", "critical"]


def metrics(df):
    out = []
    for m, g in df.groupby("model"):
        done = g[g["route"].notna()]
        exp_esc, pred_esc = g["exp_escalate"], g["route"].eq("escalate")
        tp = (exp_esc & pred_esc).sum(); fp = (~exp_esc & pred_esc).sum(); fn = (exp_esc & ~pred_esc).sum()
        out.append({
            "model": m,
            "runs": len(g),
            "task_completion_%": round(100 * len(done) / len(g), 1),
            "severity_accuracy_%": round(100 * (g["llm_severity"] == g["exp_severity"]).mean(), 1),
            "severity_within_1_%": round(100 * g.apply(lambda r: r["llm_severity"] in SEV and abs(SEV.index(r["llm_severity"]) - SEV.index(r["exp_severity"])) <= 1, axis=1).mean(), 1),
            "route_accuracy_%": round(100 * (g["route"] == g["exp_route"]).mean(), 1),
            "escalation_precision_%": round(100 * tp / (tp + fp), 1) if tp + fp else None,
            "escalation_recall_%": round(100 * tp / (tp + fn), 1) if tp + fn else None,
            "false_positive_rate_%": round(100 * fp / (~exp_esc).sum(), 1) if (~exp_esc).sum() else None,
            "hallucination_rate_%": round(100 * (g["hallucinated"] > 0).mean(), 1),
            "schema_compliance_%": round(100 * g["schema_compliance"].mean(), 1),
            "strict_json_%": round(100 * g["strict_json"].mean(), 1),
            "avg_latency_s": round(g["latency_ms"].mean() / 1000, 1),
            "avg_tokens": int(g["tokens"].mean()) if g["tokens"].notna().any() else None,
            "explanation_quality_1to5": round(g["explanation_quality"].mean(), 2) if g["explanation_quality"].notna().any() else None,
        })
    return pd.DataFrame(out)


with tab3:
    st.subheader("Open-model comparison - same cases, prompts, evidence and output schema (temperature 0)")
    bm_models = st.multiselect("Models to compare (≥3)", models, default=models[:3])
    bm_cases = st.multiselect("Test cases", [c["case"] for c in CASES], default=[c["case"] for c in CASES])
    cA, cB = st.columns(2)
    reps = cA.number_input("Repetitions per case", 1, 5, 1)
    pause = cB.number_input("Pause between runs (s) - avoids Groq free-tier rate limits", 0, 120, 30)
    st.caption("Tip: run one model at a time on the free tier. Groq free ≈ 8K tokens/min per model; "
               "Ollama models run on your PC (slower, but unlimited).")
    if st.button("▶ Run benchmark", type="primary"):
        rows, total = [], len(bm_models) * len(bm_cases) * reps
        bar = st.progress(0.0, text="Starting…")
        n = 0
        for m in bm_models:
            for c in [c for c in CASES if c["case"] in bm_cases]:
                for rep in range(reps):
                    try:
                        r = call_workflow(webhook, c["alert"], m, analyst, benchmark=True)
                    except requests.RequestException as e:
                        r = {"route": None, "flags": [f"request_error:{e}"]}
                    rows.append({
                        "model": m, "case": c["case"], "category": c["category"], "rep": rep + 1,
                        "exp_severity": c["expected"]["severity"], "exp_route": c["expected"]["route"], "exp_escalate": c["expected"]["escalate"],
                        "llm_severity": r.get("llm_severity"), "route": r.get("route"), "final_score": r.get("final_score"),
                        "confidence": r.get("confidence"), "schema_compliance": r.get("schema_compliance", 0),
                        "strict_json": r.get("strict_json", 0), "hallucinated": len(r.get("hallucinated_entities") or []),
                        "hallucinated_entities": ", ".join(r.get("hallucinated_entities") or []),
                        "latency_ms": r.get("latency_ms", r.get("_roundtrip_ms")), "tokens": r.get("tokens"),
                        "flags": ", ".join(r.get("flags") or []), "summary": r.get("summary"), "explanation_quality": None,
                    })
                    n += 1
                    if any("agent_failed" in f for f in (r.get("flags") or [])):
                        st.warning(f"{m} · {c['case']}: an agent call failed (rate limit / model unavailable?) - check n8n Executions")
                    if n < total and pause:
                        time.sleep(pause)
                    bar.progress(n / total, text=f"{m} · {c['case']} ({n}/{total})")
        df = pd.DataFrame(rows)
        path = RESULTS / f"benchmark_{dt.datetime.now():%Y%m%d_%H%M%S}.csv"
        df.to_csv(path, index=False)
        st.session_state["bm"] = df
        audit({"event": "benchmark_run", "analyst": analyst, "models": bm_models, "cases": bm_cases, "file": path.name})
        st.success(f"Saved {path.name}")

    saved = sorted(RESULTS.glob("benchmark_*.csv"), reverse=True)
    if saved and "bm" not in st.session_state:
        st.session_state["bm"] = pd.read_csv(saved[0])
    if saved:
        f = st.selectbox("Or load saved results", [p.name for p in saved])
        if st.button("Load"):
            st.session_state["bm"] = pd.read_csv(RESULTS / f)

    df = st.session_state.get("bm")
    if df is not None and len(df):
        st.markdown("**Per-run results** - score *explanation_quality* (1-5) manually using the rubric below, then metrics update.")
        st.caption("Rubric: 5 = accurate, evidence-cited, actionable · 3 = mostly correct, generic · 1 = wrong or unsupported")
        df = st.data_editor(df, width="stretch", hide_index=True,
                            column_config={"explanation_quality": st.column_config.NumberColumn(min_value=1, max_value=5, step=1)},
                            disabled=[c for c in df.columns if c != "explanation_quality"], key="bm_editor")
        df["exp_escalate"] = df["exp_escalate"].astype(bool)
        mt = metrics(df)
        st.markdown("**Model comparison**")
        st.dataframe(mt, width="stretch", hide_index=True)
        cols = st.columns(3)
        for col, metric in zip(cols, ["route_accuracy_%", "escalation_recall_%", "avg_latency_s"]):
            col.markdown(f"**{metric}**")
            col.bar_chart(mt.set_index("model")[metric])
        cols = st.columns(3)
        for col, metric in zip(cols, ["severity_accuracy_%", "hallucination_rate_%", "schema_compliance_%"]):
            col.markdown(f"**{metric}**")
            col.bar_chart(mt.set_index("model")[metric])
        st.markdown("**Route accuracy by case category**")
        st.dataframe(df.assign(correct=df["route"] == df["exp_route"]).pivot_table(index="model", columns="category", values="correct", aggfunc="mean").mul(100).round(0),
                     width="stretch")
        st.download_button("Download metrics (CSV)", mt.to_csv(index=False), "model_metrics.csv")
        st.download_button("Download scored runs (CSV)", df.to_csv(index=False), "benchmark_scored.csv")

# ================= TAB 4: guardrails =================
with tab4:
    st.subheader("Guardrails implemented in this PoC")
    st.dataframe(pd.DataFrame([
        ["Input validation", "Required fields, severity enum, 8KB size limit", "n8n: SOC Orchestrator → Input Valid?"],
        ["Prompt injection", "Pattern detection + removal; evidence framed as untrusted data; forced exception route", "Orchestrator + every agent prompt + Decision Engine"],
        ["Privacy / PII", "Email/phone redaction; usernames pseudonymised before any LLM call", "SOC Orchestrator (user_map stays in n8n)"],
        ["Model allowlist", "Only approved open-weight models; others fall back to default and are flagged", "SOC Orchestrator"],
        ["Hallucination", "Entities in LLM output not present in evidence are flagged; MITRE ID format check; blocks auto-close", "Decision Engine"],
        ["Structured output", "Per-agent required-field schema check; failures route to exception", "Decision Engine"],
        ["Decision thresholds", "50% rule score + 50% LLM score; <40 A, 40-69 H, ≥70 or crown-jewel+malicious E; confidence <0.5 → exception", "Decision Engine → Route Case"],
        ["Unsafe autonomous action", "Playbook allowlist; containment always requires approval; non-playbook actions blocked; all actions simulated", "Decision Engine + Apply Analyst Decision"],
        ["Human oversight", "Workflow pauses (Wait node) for approve / reject / escalate with mandatory comment", "H: Wait node + UI panel"],
        ["Access control", "Escalated cases can only be approved by Tier-2 role", "Apply Analyst Decision"],
        ["SLA / fail-safe", "No decision in 60 min → auto-escalate, no containment", "Wait node timeout"],
        ["Resilience", "LLM retry ×2, timeout 90s, failures continue to exception route", "HTTP agent nodes"],
        ["Auditability", "Every run, flag, score and human decision logged with analyst + timestamp; n8n execution history", "audit_log.jsonl + n8n executions"],
    ], columns=["Risk / control", "Guardrail", "Where implemented"]), width="stretch", hide_index=True)
