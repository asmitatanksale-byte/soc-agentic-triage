# Free public deployment (no card, no tunnels, laptop can be off)

```
Professor's browser ──▶ Streamlit Community Cloud (UI)  ──webhook──▶  Render free web service (n8n)  ──▶ Groq API (free)
                                                                             │
                                                                             └── Neon Postgres (free) – stores workflow + credentials
```

Hugging Face Docker Spaces became paid in 2026, so n8n runs on **Render's free web service** (no card): 512 MB RAM, sleeps after
15 min idle (wake ≈ 1 min) – the GitHub keep-alive job pings it every 10 minutes and the UI auto-retries while it wakes.

## 1. Neon database (5 min)
1. Sign up at neon.tech → create project `soc-n8n` (Singapore).
2. **Connect** → **Connection pooling OFF** → note host, database (`neondb`), user, password (ignore the `?sslmode…` part).

## 2. n8n on Render (15 min)
1. render.com → sign up with GitHub (no card) → **New + → Web Service → Existing image**.
2. Image URL: `docker.n8n.io/n8nio/n8n:2.41.6` → Next.
3. Name `soc-n8n`, Region **Singapore**, Instance type **Free** → note the URL shown (e.g. `https://soc-n8n.onrender.com`).
4. **Environment variables** → add everything in `deploy/render/env-vars.txt` with your values (Add from .env lets you paste all at once).
5. Advanced → Health check path `/healthz` → **Deploy**. Wait for "Live" (3–6 min first time).
6. Open the URL → create owner account (strong password) → Credentials → Header Auth (`Authorization` / `Bearer gsk_…`, name `LLM API Key (Bearer)`) → import `n8n/soc_triage_workflow.json` → select credential on the 5 agents → Save → **Publish**.

## 3. GitHub repository (5 min)
1. github.com → New repository `soc-agentic-triage` (Public).
2. **Add file → Upload files** → drag in everything inside the `soc-agentic` folder (incl. `.github`, `app/results/*.csv`). Never upload a file containing an API key.
3. Settings → Secrets and variables → Actions → **Variables** → `N8N_BASE_URL` = `https://soc-n8n.onrender.com` (your Render URL).

## 4. Streamlit Community Cloud UI (5 min)
1. share.streamlit.io → sign in with GitHub → **Create app** → repo `soc-agentic-triage`, branch `main`, file `app/app.py`.
2. Advanced settings → **Secrets** → paste the contents of `app/.streamlit/secrets.toml.example` with your values.
3. Deploy → you get `https://<name>.streamlit.app` → this is the link for the professor (plus the access code).

## 5. Test
Run TC01, TC04 (approve), TC08 from the public URL. First run after idle may take ~1 min (engine waking).
