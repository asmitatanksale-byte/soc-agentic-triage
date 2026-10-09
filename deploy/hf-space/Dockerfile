# n8n workflow engine for the SOC triage PoC, hosted free on Hugging Face Spaces.
# All secrets (database password, encryption key) are set as Space "Secrets", never in this file.
FROM docker.n8n.io/n8nio/n8n:2.41.6

ENV N8N_PORT=5678 \
    N8N_PROTOCOL=https \
    N8N_PROXY_HOPS=1 \
    DB_TYPE=postgresdb \
    DB_POSTGRESDB_PORT=5432 \
    DB_POSTGRESDB_SSL_ENABLED=true \
    EXECUTIONS_DATA_PRUNE=true \
    EXECUTIONS_DATA_MAX_AGE=168 \
    GENERIC_TIMEZONE=Asia/Kolkata \
    N8N_DIAGNOSTICS_ENABLED=false

EXPOSE 5678
