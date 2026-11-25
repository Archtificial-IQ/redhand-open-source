# Security Policy

RedHand is a security tool for AI agents, so I take vulnerability reports seriously.

## Reporting a Vulnerability

Please **do not open a public issue** for a security problem.

Use GitHub's private vulnerability reporting: on this repository's page choose **Security** → **Report a vulnerability**. If that option is not available, open a minimal issue stating only that you have a security report and how to reach you (with no exploit details), and I will follow up privately.

Please include:
- What you found and which component/file/route is affected
- Steps to reproduce (using local test data only)
- What an attacker gains

This is a free open-source side project, so there is no bug bounty, but I will acknowledge reports promptly and credit reporters who want credit.

## In Scope
- The code in this repository: the MCP gateway (`agentwall/`), the control plane (`services/redhand-core/`), the Python SDK (`packages/redhand-sdk/`), the dashboard (`apps/redhand-ui/`), and the database migrations (`supabase/`).
- Authentication, authorization, tenant isolation, secret redaction, Prompt Injection Radar, budget limits, and the kill switch (freeze/revoke) path.

## Out of Scope
- Any external or hosted deployment — please test only against your own local instance.
- Social engineering, physical attacks, or denial-of-service load tests against third-party infrastructure.

## Test Fixtures That Look Like Secrets
The test suites (`agentwall/tests/`, `services/redhand-core/tests/`, `packages/redhand-sdk/tests/`) contain deliberately fake key-shaped strings (such as AWS's documented example key and synthetic `sk-abc...` fixtures) strictly to test secret redaction and detection rules.

## Supported Versions
Fixes go directly to `main`.
