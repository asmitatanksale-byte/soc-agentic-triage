"""Assembles the importable n8n workflow JSON from the JS node files."""
import json, re, uuid, pathlib

D = pathlib.Path(__file__).parent / "nodes"
helper = (D / "_parse_helper.js").read_text()
js = lambda f, h=False: (helper + "\n" if h else "") + (D / f).read_text()
branches = dict(re.findall(r"//@@ (\w+)\n(.*?)(?=//@@ |\Z)", (D / "08_branches.js").read_text(), re.S))

nodes, conns = [], {}
CRED = {"httpHeaderAuth": {"id": "llmHeaderAuth1", "name": "LLM API Key (Bearer)"}}


def node(name, type_, ver, params, pos, **extra):
    nodes.append({"id": str(uuid.uuid4()), "name": name, "type": type_, "typeVersion": ver,
                  "position": pos, "parameters": params, **extra})


def code(name, src, pos):
    node(name, "n8n-nodes-base.code", 2, {"jsCode": src}, pos)


def llm(name, pos):
    node(name, "n8n-nodes-base.httpRequest", 4.2, {
        "method": "POST",
        "url": "={{ $('SOC Orchestrator').first().json.llm_url }}",
        "authentication": "genericCredentialType",
        "genericAuthType": "httpHeaderAuth",
        "sendBody": True, "specifyBody": "json",
        "jsonBody": "={{ JSON.stringify($json.llm_request) }}",
        "options": {"timeout": 300000},
    }, pos, credentials=CRED, retryOnFail=True, maxTries=3, waitBetweenTries=5000, onError="continueRegularOutput")


def link(a, b, out=0, inp=0):
    conns.setdefault(a, {"main": []})
    m = conns[a]["main"]
    while len(m) <= out:
        m.append([])
    m[out].append({"node": b, "type": "main", "index": inp})


def respond(name, pos, code_=200, body=None):
    p = {"respondWith": "firstIncomingItem", "options": {"responseCode": code_}}
    if body:
        p = {"respondWith": "json", "responseBody": body, "options": {"responseCode": code_}}
    node(name, "n8n-nodes-base.respondToWebhook", 1.1, p, pos)


def if_node(name, expr, pos):
    node(name, "n8n-nodes-base.if", 2, {
        "conditions": {
            "options": {"caseSensitive": True, "leftValue": "", "typeValidation": "loose"},
            "conditions": [{"id": str(uuid.uuid4()), "leftValue": expr, "rightValue": "",
                            "operator": {"type": "boolean", "operation": "true", "singleValue": True}}],
            "combinator": "and"},
        "options": {}}, pos)



# ======================= LAYOUT =======================
# Two rows so the whole board fits one screen:
#   Row 1:  [1 INTAKE & GUARDRAILS]  [2 SPECIALIST AI AGENTS: tools on top, LLM agents below]
#   Row 2:  [3 DECISION]  [4 OUTCOMES A/H/E/X]  [5 HUMAN-IN-THE-LOOP]
R1, R2 = 0, 800          # row baselines (y)
AX = [960 + 250 * i for i in range(5)]   # agent-pair columns

# ---------- 1. intake ----------
node("Alert In (Webhook)", "n8n-nodes-base.webhook", 2,
     {"httpMethod": "POST", "path": "soc-triage", "responseMode": "responseNode", "options": {}},
     [0, R1 + 100], webhookId=str(uuid.uuid4()))
code("SOC Orchestrator", js("01_orchestrator.js"), [250, R1 + 100])
if_node("Input Valid?", "={{ $json.valid }}", [500, R1 + 100])
respond("Reject Bad Input", [700, R1 + 300], 400,
        "={{ JSON.stringify({status: 'rejected_invalid_input', errors: $json.errors, flags: $json.flags}) }}")

# ---------- 2. agents (tool above, LLM agent below) ----------
pairs = [("SIEM Search (Tool)", "02_correlation_tool.js", False, "Correlation Agent"),
         ("Threat Intel DB (Tool)", "03_ti_tool.js", False, "Threat Intel Agent"),
         ("CMDB & IAM (Tool)", "04_asset_tool.js", False, "Asset Context Agent"),
         ("Risk Evidence", "05_risk_pack.js", True, "Risk Agent"),
         ("Summary Evidence", "06_summary_pack.js", True, "Summary Agent")]
for (tool, f, h, agent), x in zip(pairs, AX):
    code(tool, js(f, h), [x, R1 + 20])
    llm(agent, [x, R1 + 240])

# ---------- 3. decision ----------
code("Decision Engine", js("07_decision_engine.js", True), [0, R2 + 220])
routes = ["auto_close", "hitl", "escalate", "exception"]
node("Route A / H / E / X", "n8n-nodes-base.switch", 3, {
    "rules": {"values": [{
        "conditions": {"options": {"caseSensitive": True, "leftValue": "", "typeValidation": "strict"},
                       "conditions": [{"leftValue": "={{ $json.route }}", "rightValue": r,
                                       "operator": {"type": "string", "operation": "equals"}}],
                       "combinator": "and"},
        "renameOutput": True, "outputKey": r} for r in routes]},
    "options": {}}, [260, R2 + 220])

# ---------- 4. outcomes ----------
code("A: Auto-Close", branches["AUTO_CLOSE"], [640, R2 + 20])
respond("Reply: Closed", [880, R2 + 20])
code("E: Escalate Tier-2", branches["ESCALATE"], [640, R2 + 260])
code("X: Exception Queue", branches["EXCEPTION"], [640, R2 + 440])
code("H: Prepare Review", branches["PREP_HITL"], [880, R2 + 260])
respond("Reply: Awaiting Analyst", [1120, R2 + 260])

# ---------- 5. human in the loop ----------
if_node("Benchmark Run?", "={{ $json.benchmark }}", [1440, R2 + 260])
node("End (Benchmark)", "n8n-nodes-base.noOp", 1, {}, [1680, R2 + 100])
node("H: Wait for Analyst", "n8n-nodes-base.wait", 1.1, {
    "resume": "webhook", "httpMethod": "POST", "responseMode": "lastNode",
    "limitWaitTime": True, "limitType": "afterTimeInterval", "resumeAmount": 60, "resumeUnit": "minutes",
    "options": {}}, [1680, R2 + 380], webhookId=str(uuid.uuid4()))
code("Apply Analyst Decision", branches["APPLY_DECISION"], [1920, R2 + 380])

# ---------- connections ----------
def chain(*names):
    for a, b in zip(names, names[1:]):
        link(a, b)

chain("Alert In (Webhook)", "SOC Orchestrator", "Input Valid?")
link("Input Valid?", "SIEM Search (Tool)", 0)
link("Input Valid?", "Reject Bad Input", 1)
seq = []
for tool, _, _, agent in pairs:
    seq += [tool, agent]
chain(*seq, "Decision Engine", "Route A / H / E / X")
link("Route A / H / E / X", "A: Auto-Close", 0)
link("Route A / H / E / X", "H: Prepare Review", 1)
link("Route A / H / E / X", "E: Escalate Tier-2", 2)
link("Route A / H / E / X", "X: Exception Queue", 3)
link("A: Auto-Close", "Reply: Closed")
link("E: Escalate Tier-2", "H: Prepare Review")
link("X: Exception Queue", "H: Prepare Review")
chain("H: Prepare Review", "Reply: Awaiting Analyst", "Benchmark Run?")
link("Benchmark Run?", "End (Benchmark)", 0)
link("Benchmark Run?", "H: Wait for Analyst", 1)
link("H: Wait for Analyst", "Apply Analyst Decision")

# ---------- section frames (sticky notes drawn behind the nodes) ----------
def sticky(content, x, y, w, h, color):
    node(f"Note {len(nodes)}", "n8n-nodes-base.stickyNote", 1,
         {"content": content, "width": w, "height": h, "color": color}, [x, y])

sticky("# 🛡️ Governed Agentic AI - SOC Alert Triage\n"
       "**UI alert → Intake guardrails → 5 AI agents → Decision Engine → A / H / E / X → Human approval**  ·  "
       "**A** = Autonomous  ·  **H** = Human-in-the-Loop  ·  **E** = Escalation  ·  **X** = Exception",
       -100, -330, 2180, 170, 7)
sticky("# 1 · INTAKE & GUARDRAILS\n**A** · Validate alert, block prompt injection, redact PII, pseudonymise user, allow-listed models only",
       -100, -140, 900, 600, 5)
sticky("# 2 · SPECIALIST AI AGENTS\n**A** · Top row = data tools (mock SIEM / Threat-Intel / CMDB).  Bottom row = LLM agents (open models). Evidence-only, JSON-only, retry ×3",
       880, -140, 1200, 600, 4)
sticky("# 3 · DECISION\n**A** · 50% rule score + 50% AI score, hallucination & schema checks, playbook allow-list\n\n← from Summary Agent",
       -100, R2 - 140, 600, 600, 6)
sticky("# 4 · OUTCOMES\n**A** auto-close (<40)  ·  **H** review (40-69)\n**E** escalate (≥70)  ·  **X** exception",
       540, R2 - 140, 760, 760, 3)
sticky("# 5 · HUMAN-IN-THE-LOOP  [H]\nWorkflow pauses for analyst approve / reject / escalate. Containment never automatic. 60-min SLA → auto-escalate",
       1340, R2 - 140, 740, 760, 2)

# stickies first so they render behind nodes
nodes.sort(key=lambda n: n["type"] != "n8n-nodes-base.stickyNote")

# ---------- rename node references inside code / expressions ----------
RENAME = {
    "Correlation Tool (SIEM search)": "SIEM Search (Tool)",
    "Threat Intel Tool (IOC lookup)": "Threat Intel DB (Tool)",
    "Asset & Identity Tool (CMDB/IAM)": "CMDB & IAM (Tool)",
    "Alert Correlation Agent": "Correlation Agent",
    "Threat Intelligence Agent": "Threat Intel Agent",
    "Risk Prioritisation Agent": "Risk Agent",
    "Incident Summary Agent": "Summary Agent",
    "Risk Evidence Pack": "Risk Evidence",
    "Summary Evidence Pack": "Summary Evidence",
    "Decision Engine (Score + Guardrails)": "Decision Engine",
    "Prepare HITL Request": "H: Prepare Review",
}
for n in nodes:
    if "jsCode" in n["parameters"]:
        for old, new in RENAME.items():
            n["parameters"]["jsCode"] = n["parameters"]["jsCode"].replace(f"'{old}'", f"'{new}'")

names = {n["name"] for n in nodes}
for n in nodes:
    for ref in re.findall(r"\$\('([^']+)'\)", json.dumps(n["parameters"])):
        assert ref in names, f"{n['name']} references missing node {ref}"

wf = {"name": "SOC Agentic Triage - Governed (PoC)", "nodes": nodes, "connections": conns,
      "settings": {"executionOrder": "v1", "saveDataSuccessExecution": "all", "saveManualExecutions": True},
      "pinData": {}, "active": False}
out = pathlib.Path(__file__).parent / "soc_triage_workflow.json"
out.write_text(json.dumps(wf, indent=2))
print("wrote", out, len(nodes), "nodes")
