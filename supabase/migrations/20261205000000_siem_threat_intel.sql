-- =============================================================================
-- Phase 2 Enterprise: OCSF v1.1.0 SIEM connectors, outbox & STIX/TAXII 2.1 feeds
-- Rollback: supabase/rollbacks/20261205000000_siem_threat_intel.down.sql
-- =============================================================================

BEGIN;

CREATE TABLE public.siem_connectors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    connector_type TEXT NOT NULL CHECK (connector_type IN ('splunk_hec', 'sentinel_logs', 'google_secops')),
    name TEXT NOT NULL CHECK (char_length(btrim(name)) BETWEEN 2 AND 120),
    endpoint_url TEXT NOT NULL CHECK (char_length(btrim(endpoint_url)) BETWEEN 12 AND 512),
    encrypted_token TEXT NOT NULL,
    token_hint TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    last_shipped_at TIMESTAMPTZ,
    last_error TEXT,
    created_by UUID REFERENCES public.operators(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_siem_connectors_org ON public.siem_connectors(organization_id, created_at DESC);
ALTER TABLE public.siem_connectors ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.siem_outbox (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    connector_id UUID NOT NULL REFERENCES public.siem_connectors(id) ON DELETE CASCADE,
    event_kind TEXT NOT NULL,
    ocsf_payload JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'delivered', 'dead_letter')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_siem_outbox_pending ON public.siem_outbox(status, next_attempt_at) WHERE status = 'pending';
CREATE INDEX idx_siem_outbox_org ON public.siem_outbox(organization_id, created_at DESC);
ALTER TABLE public.siem_outbox ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.threat_intel_feeds (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (char_length(btrim(name)) BETWEEN 2 AND 120),
    collection_url TEXT NOT NULL CHECK (char_length(btrim(collection_url)) BETWEEN 12 AND 512),
    encrypted_auth TEXT,
    token_hint TEXT,
    poll_interval_minutes INTEGER NOT NULL DEFAULT 5 CHECK (poll_interval_minutes BETWEEN 1 AND 1440),
    enabled BOOLEAN NOT NULL DEFAULT true,
    last_synced_at TIMESTAMPTZ,
    last_indicator_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_by UUID REFERENCES public.operators(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_threat_intel_feeds_org ON public.threat_intel_feeds(organization_id, created_at DESC);
ALTER TABLE public.threat_intel_feeds ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.threat_intel_indicators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    feed_id UUID NOT NULL REFERENCES public.threat_intel_feeds(id) ON DELETE CASCADE,
    indicator_type TEXT NOT NULL CHECK (indicator_type IN ('domain', 'ipv4', 'sha256')),
    indicator_value TEXT NOT NULL CHECK (char_length(btrim(indicator_value)) BETWEEN 3 AND 256),
    confidence INTEGER NOT NULL DEFAULT 80 CHECK (confidence BETWEEN 0 AND 100),
    stix_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, indicator_type, indicator_value)
);

CREATE INDEX idx_threat_intel_indicators_org ON public.threat_intel_indicators(organization_id, created_at DESC);
ALTER TABLE public.threat_intel_indicators ENABLE ROW LEVEL SECURITY;

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
    jsonb_build_object('table', 'threat_intel_indicators', 'scope', 'org', 'exclude', jsonb_build_array())
)
$$;

COMMIT;
