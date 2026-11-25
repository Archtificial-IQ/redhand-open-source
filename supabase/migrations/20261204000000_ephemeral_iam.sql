-- =============================================================================
-- Phase 1 Enterprise: Ephemeral IAM Broker policies, cloud connections & audit
-- Rollback: supabase/rollbacks/20261204000000_ephemeral_iam.down.sql
-- =============================================================================

BEGIN;

CREATE TABLE public.iam_cloud_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    provider TEXT NOT NULL CHECK (provider IN ('aws_sts', 'gcp_sts')),
    display_name TEXT NOT NULL CHECK (char_length(btrim(display_name)) BETWEEN 2 AND 120),
    principal_identifier TEXT NOT NULL CHECK (char_length(btrim(principal_identifier)) BETWEEN 8 AND 512),
    region_or_project TEXT NOT NULL DEFAULT 'global',
    status TEXT NOT NULL DEFAULT 'verified' CHECK (status IN ('verified', 'disabled')),
    created_by UUID REFERENCES public.operators(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_iam_cloud_connections_org ON public.iam_cloud_connections(organization_id, created_at DESC);
ALTER TABLE public.iam_cloud_connections ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.iam_broker_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    external_agent_id TEXT NOT NULL CHECK (char_length(btrim(external_agent_id)) BETWEEN 1 AND 128),
    tool_name TEXT NOT NULL CHECK (char_length(btrim(tool_name)) BETWEEN 1 AND 256),
    provider TEXT NOT NULL CHECK (provider IN ('aws_sts', 'gcp_sts')),
    target_principal TEXT NOT NULL CHECK (char_length(btrim(target_principal)) BETWEEN 8 AND 512),
    target_resource TEXT NOT NULL CHECK (target_resource <> '*' AND char_length(btrim(target_resource)) BETWEEN 8 AND 512),
    allowed_actions JSONB NOT NULL DEFAULT '[]'::jsonb,
    ttl_seconds INTEGER NOT NULL DEFAULT 60 CHECK (ttl_seconds BETWEEN 15 AND 43200),
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_by UUID REFERENCES public.operators(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, external_agent_id, tool_name, provider)
);

CREATE INDEX idx_iam_broker_policies_org ON public.iam_broker_policies(organization_id, created_at DESC);
ALTER TABLE public.iam_broker_policies ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.iam_mint_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    external_agent_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    provider TEXT NOT NULL CHECK (provider IN ('aws_sts', 'gcp_sts')),
    token_jti TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    span_id TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('minted', 'denied')),
    detail TEXT,
    expires_at TIMESTAMPTZ,
    mint_latency_ms DOUBLE PRECISION NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_iam_mint_events_org ON public.iam_mint_events(organization_id, created_at DESC);
ALTER TABLE public.iam_mint_events ENABLE ROW LEVEL SECURITY;

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
    jsonb_build_object('table', 'iam_mint_events', 'scope', 'org', 'exclude', jsonb_build_array('token_jti'))
)
$$;

COMMIT;
