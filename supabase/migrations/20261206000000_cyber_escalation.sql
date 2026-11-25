-- =============================================================================
-- Phase 3 Enterprise: Async Deep Cyber-Model Escalation policies & triage queue
-- Rollback: supabase/rollbacks/20261206000000_cyber_escalation.down.sql
-- =============================================================================

BEGIN;

CREATE TABLE public.escalation_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (char_length(btrim(name)) BETWEEN 2 AND 120),
    trigger_kind TEXT NOT NULL CHECK (trigger_kind IN ('onnx_borderline', 'delegation_depth', 'obfuscation_drift')),
    threshold_value DOUBLE PRECISION NOT NULL CHECK (threshold_value >= 0),
    provider TEXT NOT NULL CHECK (provider IN ('managed_redhand', 'anthropic', 'openai', 'gemini_vertex', 'custom_vpc')),
    endpoint_url TEXT NOT NULL CHECK (char_length(btrim(endpoint_url)) BETWEEN 12 AND 512),
    model_name TEXT NOT NULL CHECK (char_length(btrim(model_name)) BETWEEN 2 AND 128),
    encrypted_api_key TEXT NOT NULL,
    key_hint TEXT NOT NULL,
    circuit_breaker_action TEXT NOT NULL CHECK (circuit_breaker_action IN ('freeze_agent', 'safe_mode', 'hitl_review')),
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_by UUID REFERENCES public.operators(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_escalation_policies_org ON public.escalation_policies(organization_id, created_at DESC);
ALTER TABLE public.escalation_policies ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.escalation_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    policy_id UUID NOT NULL REFERENCES public.escalation_policies(id) ON DELETE CASCADE,
    external_agent_id TEXT NOT NULL,
    trigger_kind TEXT NOT NULL,
    signal_score DOUBLE PRECISION NOT NULL DEFAULT 0,
    delegation_depth INTEGER NOT NULL DEFAULT 1,
    redacted_trace TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
    verdict TEXT CHECK (verdict IN ('malicious', 'benign', 'inconclusive')),
    confidence DOUBLE PRECISION,
    action_taken TEXT,
    reasoning_summary TEXT,
    review_latency_ms DOUBLE PRECISION,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_escalation_jobs_pending ON public.escalation_jobs(status, created_at) WHERE status = 'pending';
CREATE INDEX idx_escalation_jobs_org ON public.escalation_jobs(organization_id, created_at DESC);
ALTER TABLE public.escalation_jobs ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION public.tenant_data_manifest() RETURNS jsonb
LANGUAGE sql IMMUTABLE
AS $$
SELECT jsonb_build_array(
    jsonb_build_object('table', 'organizations', 'scope', 'self', 'exclude', jsonb_build_array('siem_webhook_url')),
    jsonb_build_object('table', 'organization_members', 'scope', 'members', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'agents', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'agent_keys', 'scope', 'org', 'exclude', jsonb_build_array('key_hash')),
    jsonb_build_object('table', 'agent_destinations', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'agent_budget_state', 'scope', 'agent', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'agent_usage_daily', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'agent_model_daily', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'agent_model_measured_daily', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'agent_tool_hourly', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'agent_events', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'event_batches', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'event_chain_heads', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'execution_traces', 'scope', 'org', 'exclude', jsonb_build_array('ephemeral_token_jti')),
    jsonb_build_object('table', 'hitl_interventions', 'scope', 'org', 'exclude', jsonb_build_array('notification_webhook_url', 'resume_webhook_url')),
    jsonb_build_object('table', 'security_events', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'security_findings', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'radar_suppressions', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'radar_rule_counts', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'radar_scan_counts', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'honeytokens', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'honey_tools', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'honeytrips', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'mcp_servers', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'mcp_tool_pins', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'approved_models', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'sdk_api_keys', 'scope', 'org', 'exclude', jsonb_build_array('key_hash')),
    jsonb_build_object('table', 'telegram_links', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'telegram_link_codes', 'scope', 'org', 'exclude', jsonb_build_array('code_hash')),
    jsonb_build_object('table', 'member_invites', 'scope', 'org', 'exclude', jsonb_build_array('token_hash')),
    jsonb_build_object('table', 'control_audit_log', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'iam_cloud_connections', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'iam_broker_policies', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'iam_mint_events', 'scope', 'org', 'exclude', jsonb_build_array('token_jti')),
    jsonb_build_object('table', 'siem_connectors', 'scope', 'org', 'exclude', jsonb_build_array('encrypted_token')),
    jsonb_build_object('table', 'siem_outbox', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'threat_intel_feeds', 'scope', 'org', 'exclude', jsonb_build_array('encrypted_auth')),
    jsonb_build_object('table', 'threat_intel_indicators', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'escalation_policies', 'scope', 'org', 'exclude', jsonb_build_array('encrypted_api_key')),
    jsonb_build_object('table', 'escalation_jobs', 'scope', 'org', 'exclude', jsonb_build_array())
)
$$;

COMMIT;
