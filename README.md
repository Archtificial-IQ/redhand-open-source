# RedHand

I built RedHand as a free, open-source side project for AI agent safety. It sits between your AI agents and the tools they call (via MCP) so you stay in control when an agent goes off-script.

## What RedHand Does

- **Kill switch** — Give every agent a scoped passport and freeze or revoke one agent (or all of them) in seconds.
- **Spending & call limits** — Cap daily tool calls and model spend per agent before a runaway loop drains your budget.
- **Action log** — Record every tool call, decision, and redacted payload in a searchable timeline.
- **Prompt injection detection** — Inspect tool descriptions and tool outputs for indirect prompt injection, secret leaks, loop behavior, and unapproved destinations.

> **Scope note:** RedHand protects agents whose tool traffic goes through the AgentWall MCP gateway. Agents calling external APIs directly with raw keys bypass the gateway.

## Demo

<!-- Replace this placeholder with a screenshot or demo GIF once recorded -->
![RedHand Dashboard Demo — screenshot/GIF placeholder](docs/assets/demo-placeholder.gif)
*Demo screenshot / GIF coming soon.*

## Quick Start

The fastest way to run everything locally (control plane, MCP gateway, demo MCP server, and dashboard) is with Docker Compose:

```bash
git clone https://github.com/Archtificial-IQ/redhand-open-source.git
cd redhand-open-source
docker compose up --build
```

Once the containers are up:

1. Open the dashboard at **http://localhost:3000** and click **Continue as Owner** (local dev mode uses an in-memory store — no database setup needed).
2. On the **Passports** page, register the bundled demo MCP server:
   - Slug: `xero`
   - URL: `http://demo-mcp:9100/mcp` *(use `http://localhost:9100/mcp` if running without Docker)*
3. Create an agent passport with scope `xero` / `list_invoices` and copy the agent key.
4. Exchange the agent key for a short-lived access token and call a tool through the gateway:

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/v1/agent-auth/token \
  -H "Authorization: Bearer YOUR_AGENT_KEY_HERE" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

# Allowed (in scope)
curl -s http://localhost:8080/mcp/xero \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_invoices","arguments":{}}}'
```

Try calling `delete_invoice` (blocked — out of scope) or hit **Freeze** on the agent in the dashboard and repeat the `list_invoices` call — the gateway denies it within ~2 seconds.

## Run Without Docker (Local Dev)

Prerequisites: Python 3.11+, [uv](https://github.com/astral-sh/uv), Node.js 18+.

```bash
uv sync
npm --prefix apps/redhand-ui install
export RH_SERVICE_TOKEN=$(openssl rand -base64 32)
```

Start the four local processes (each in its own terminal):

```bash
# 1. Control plane (:8000)
ENVIRONMENT=development ALLOW_INSECURE_MCP_URLS=true INTERNAL_SERVICE_TOKEN=$RH_SERVICE_TOKEN \
  uv run --directory services/redhand-core uvicorn redhand_core.main:app --port 8000

# 2. AgentWall MCP gateway (:8080)
AGENTWALL_CORE_SERVICE_TOKEN=$RH_SERVICE_TOKEN AGENTWALL_ALLOW_INSECURE_UPSTREAMS=true \
  uv run uvicorn agentwall.src.main:app --port 8080

# 3. Demo MCP server (:9100)
uv run uvicorn examples.demo_mcp_server:app --port 9100

# 4. Dashboard (:3000)
npm run dev
```

Copy [`.env.example`](.env.example) to `.env` when configuring optional PostgreSQL/Supabase persistence, Telegram panic commands, or Slack approvals.

## What's Inside

| Path | Description |
|---|---|
| `services/redhand-core/` | FastAPI control plane (passports, kill switch, spend limits, action log, auth) |
| `agentwall/` | MCP security gateway (enforcement, prompt injection Radar, budgets, secret redaction) |
| `apps/redhand-ui/` | Next.js dashboard |
| `packages/redhand-sdk/` | Python SDK (`@guard`, `redhand scan`, `redhand fuzz`) |
| `examples/` | Local demo MCP server and sample agent scripts |
| `supabase/migrations/` | PostgreSQL / Supabase schema migrations for persistent deployments |
| `docs/` | Threat model, OpenAPI specs, and feature guides |

## Running Tests

```bash
uv run pytest -q
npm --prefix apps/redhand-ui test
```

## Feedback Welcome

I built RedHand in the open and would love to hear what works, what breaks, or what safety controls you wish existed for your agents.

- Bug reports, ideas, and questions: **[Open a GitHub Issue](https://github.com/Archtificial-IQ/redhand-open-source/issues)**
- Security vulnerabilities: see [SECURITY.md](SECURITY.md)

## License

Apache License 2.0 — see [LICENSE](LICENSE).
