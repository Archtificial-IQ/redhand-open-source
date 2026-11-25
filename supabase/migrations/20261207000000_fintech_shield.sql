-- =============================================================================
-- Phase 6 S1: Fintech Shield settings and payment-tool bindings (docs/plans/phase6-fintech-shield.md, ADR 0033).
-- Rollback: supabase/rollbacks/20261207000000_fintech_shield.down.sql
--
-- Per organization: a mode (off, observe, enforce; default observe) and holiday dates for the off-hours rule. Per MCP server: the payment tools
-- an operator has bound, each naming which argument path holds the amount, the currency (or a fixed currency) and, optionally, the payee.
-- Only bound tools are ever judged by the gateway (S2), so the observe default is inert until an organization binds a tool.
-- Bindings store argument PATHS, never values: no amount, currency of a call or payee is stored by this migration.
-- Additive: an older core and an older gateway keep working (the gateway ignores context fields it does not know).
--
-- Changed here: the audit action list, tenant_data_manifest(). New: organizations.fintech_*, the mcp_server_tool_bindings table,
-- fintech_settings(), control_fintech_settings(), control_fintech_binding_upsert(), control_fintech_binding_remove().
-- Findings (kind fintech, RAD-FIN rule ids) are NOT added here: they arrive with the gateway stage in S2.
-- =============================================================================

BEGIN;

ALTER TABLE public.control_audit_log DROP CONSTRAINT control_audit_log_action_check;
ALTER TABLE public.control_audit_log ADD CONSTRAINT control_audit_log_action_check CHECK (action IN (
    'passport.created', 'passport.frozen', 'passport.unfrozen', 'passport.revoked',
    'passport.scopes_changed', 'passport.renewed', 'passport.key_rotated',
    'organization.frozen_all', 'mcp_server.registered', 'mcp_server.deactivated',
    'telegram.linked', 'telegram.unlinked',
    'passport.safe_mode_enabled', 'passport.safe_mode_disabled',
    'organization.safe_mode_enabled', 'organization.safe_mode_disabled',
    'passport.budget_changed', 'organization.budget_default_changed',
    'organization.blackbox_retention_changed', 'organization.blackbox_purged',
    'organization.payload_capture_changed',
    'organization.blackbox_payload_viewed', 'organization.blackbox_exported',
    'organization.blackbox_payloads_cleared',
    'honeytoken.created', 'honeytoken.retired', 'honeytoken.tripped',
    'honey_tool.created', 'honey_tool.retired', 'honey_tool.tripped',
    'tool_pin.pending', 'tool_pin.approved', 'tool_pin.rejected', 'tool_pin.approved_all',
    'mcp_server.pin_mode_changed',
    'organization.radar_settings_changed', 'radar_finding.reviewed',
    'radar_suppression.created', 'radar_suppression.revoked',
    'organization.loop_settings_changed',
    'passport.destination_added', 'passport.destination_removed', 'passport.destination_mode_changed',
    'organization.risk_ladder_changed',
    'passport.timeline_exported',
    'passport.spend_limit_changed',
    'organization.approved_models_changed',
    'sdk_key.created', 'sdk_key.revoked',
    'passport.promoted',
    'organization.created', 'member.invited', 'member.invite_revoked', 'member.joined', 'member.removed', 'member.role_changed',
    'organization.exported', 'organization.deletion_requested', 'organization.deletion_cancelled',
    'organization.fintech_settings_changed',
    'mcp_server.fintech_binding_added', 'mcp_server.fintech_binding_changed', 'mcp_server.fintech_binding_removed'
));

ALTER TABLE public.organizations
    ADD COLUMN fintech_shield_mode TEXT NOT NULL DEFAULT 'observe' CHECK (fintech_shield_mode IN ('off', 'observe', 'enforce')),
    ADD COLUMN fintech_shield_mode_changed_at TIMESTAMPTZ,
    ADD COLUMN fintech_holidays DATE[] NOT NULL DEFAULT '{}' CHECK (cardinality(fintech_holidays) <= 60 AND array_position(fintech_holidays, NULL) IS NULL);

-- One row per bound payment tool on one MCP server. A path is a dotted argument path with optional list selectors (payee.vpa,
-- payments[*].amount): the same grammar the gateway's rule engine accepts, deliberately without filters or recursion.
CREATE TABLE public.mcp_server_tool_bindings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    server_id UUID NOT NULL REFERENCES public.mcp_servers(id) ON DELETE CASCADE,
    tool TEXT NOT NULL CHECK (tool ~ '^[A-Za-z0-9_.-]{1,128}$'),
    amount_path TEXT NOT NULL CHECK (char_length(amount_path) <= 256 AND amount_path ~ '^[A-Za-z_][A-Za-z0-9_-]*(\[(\*|[0-9]+)\])?(\.[A-Za-z_][A-Za-z0-9_-]*(\[(\*|[0-9]+)\])?)*$'),
    currency_path TEXT CHECK (currency_path IS NULL OR (char_length(currency_path) <= 256 AND currency_path ~ '^[A-Za-z_][A-Za-z0-9_-]*(\[(\*|[0-9]+)\])?(\.[A-Za-z_][A-Za-z0-9_-]*(\[(\*|[0-9]+)\])?)*$')),
    fixed_currency TEXT CHECK (fixed_currency IS NULL OR fixed_currency ~ '^[A-Z]{3}$'),
    beneficiary_path TEXT CHECK (beneficiary_path IS NULL OR (char_length(beneficiary_path) <= 256 AND beneficiary_path ~ '^[A-Za-z_][A-Za-z0-9_-]*(\[(\*|[0-9]+)\])?(\.[A-Za-z_][A-Za-z0-9_-]*(\[(\*|[0-9]+)\])?)*$')),
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (server_id, tool),
    -- exactly one way to know the currency
    CHECK ((currency_path IS NULL) <> (fixed_currency IS NULL))
);
CREATE INDEX idx_mcp_server_tool_bindings_server ON public.mcp_server_tool_bindings(organization_id, server_id);
ALTER TABLE public.mcp_server_tool_bindings ENABLE ROW LEVEL SECURITY;  -- core uses the service role; no policies, nobody else reads it

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
    jsonb_build_object('table', 'mcp_server_tool_bindings', 'scope', 'org', 'exclude', jsonb_build_array()),
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

-- -----------------------------------------------------------------------------
-- fintech_settings(): the organization's mode, holidays and every binding (with its server's slug), for the settings page.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fintech_settings(p_org uuid)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SET search_path = public, pg_temp
AS $$
DECLARE
    v_org public.organizations%ROWTYPE;
BEGIN
    SELECT * INTO v_org FROM public.organizations WHERE id = p_org;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'organization not found' USING ERRCODE = 'no_data_found';
    END IF;
    RETURN jsonb_build_object(
        'fintech_shield_mode', v_org.fintech_shield_mode, 'fintech_shield_mode_changed_at', v_org.fintech_shield_mode_changed_at,
        'fintech_holidays', to_jsonb(v_org.fintech_holidays),
        'bindings', COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                'id', b.id, 'server_id', b.server_id, 'server_slug', s.slug, 'tool', b.tool, 'amount_path', b.amount_path,
                'currency_path', b.currency_path, 'fixed_currency', b.fixed_currency, 'beneficiary_path', b.beneficiary_path,
                'updated_at', b.updated_at) ORDER BY s.slug, b.tool)
            FROM public.mcp_server_tool_bindings b JOIN public.mcp_servers s ON s.id = b.server_id
            WHERE b.organization_id = p_org), '[]'::jsonb));
END;
$$;

-- -----------------------------------------------------------------------------
-- control_fintech_settings(): compare-and-set on the mode the caller saw, plus the holiday list; idempotent, audited. Enforce needs at least one
-- binding (with none, enforce would judge nothing while looking switched on). The role check and the confirmations live in redhand-core.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.control_fintech_settings(
    p_org uuid, p_actor uuid, p_mode text, p_expected_mode text, p_holidays date[], p_reason text)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_org public.organizations%ROWTYPE;
    v_holidays date[];
BEGIN
    IF p_mode IS NULL OR p_mode NOT IN ('off', 'observe', 'enforce') OR (p_reason IS NOT NULL AND char_length(p_reason) > 300) THEN
        RAISE EXCEPTION 'mode must be off, observe or enforce' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_holidays IS NULL OR cardinality(p_holidays) > 60 OR array_position(p_holidays, NULL) IS NOT NULL THEN
        RAISE EXCEPTION 'holidays are at most 60 dates' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    v_holidays := ARRAY(SELECT DISTINCT d FROM unnest(p_holidays) AS d ORDER BY d);
    SELECT * INTO v_org FROM public.organizations WHERE id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'organization not found' USING ERRCODE = 'no_data_found';
    END IF;
    IF v_org.fintech_shield_mode IS DISTINCT FROM p_expected_mode THEN
        RETURN jsonb_build_object('conflict', true, 'fintech_shield_mode', v_org.fintech_shield_mode);
    END IF;
    IF p_mode = 'enforce' AND v_org.fintech_shield_mode <> 'enforce'
       AND NOT EXISTS (SELECT 1 FROM public.mcp_server_tool_bindings WHERE organization_id = p_org) THEN
        RETURN jsonb_build_object('conflict', false, 'changed', false, 'no_bindings', true, 'fintech_shield_mode', v_org.fintech_shield_mode);
    END IF;
    IF v_org.fintech_shield_mode = p_mode AND v_org.fintech_holidays = v_holidays THEN
        RETURN jsonb_build_object('conflict', false, 'changed', false, 'fintech_shield_mode', p_mode);
    END IF;
    UPDATE public.organizations
       SET fintech_shield_mode = p_mode,
           fintech_shield_mode_changed_at = CASE WHEN fintech_shield_mode <> p_mode THEN now() ELSE fintech_shield_mode_changed_at END,
           fintech_holidays = v_holidays
     WHERE id = p_org;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'organization.fintech_settings_changed', 'organization', p_org, p_reason,
            jsonb_build_object('old_mode', v_org.fintech_shield_mode, 'new_mode', p_mode,
                               'holidays', cardinality(v_holidays), 'holidays_changed', v_org.fintech_holidays IS DISTINCT FROM v_holidays));
    RETURN jsonb_build_object('conflict', false, 'changed', true, 'fintech_shield_mode', p_mode);
END;
$$;

-- -----------------------------------------------------------------------------
-- control_fintech_binding_upsert(): binds one tool on one of the organization's servers, or changes its paths. Idempotent (the same paths again
-- write nothing), at most 50 bindings per server, tenant-checked (the server must belong to the organization), audited.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.control_fintech_binding_upsert(
    p_org uuid, p_actor uuid, p_server uuid, p_tool text, p_amount_path text, p_currency_path text, p_fixed_currency text,
    p_beneficiary_path text, p_reason text)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_existing public.mcp_server_tool_bindings%ROWTYPE;
    v_id uuid;
BEGIN
    IF p_reason IS NOT NULL AND char_length(p_reason) > 300 THEN
        RAISE EXCEPTION 'the reason is at most 300 characters' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM 1 FROM public.mcp_servers WHERE id = p_server AND organization_id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'server not found' USING ERRCODE = 'no_data_found';
    END IF;
    SELECT * INTO v_existing FROM public.mcp_server_tool_bindings WHERE server_id = p_server AND tool = p_tool;
    IF FOUND THEN
        IF v_existing.amount_path = p_amount_path AND v_existing.currency_path IS NOT DISTINCT FROM p_currency_path
           AND v_existing.fixed_currency IS NOT DISTINCT FROM p_fixed_currency
           AND v_existing.beneficiary_path IS NOT DISTINCT FROM p_beneficiary_path THEN
            RETURN jsonb_build_object('id', v_existing.id, 'created', false, 'changed', false);
        END IF;
        UPDATE public.mcp_server_tool_bindings
           SET amount_path = p_amount_path, currency_path = p_currency_path, fixed_currency = p_fixed_currency,
               beneficiary_path = p_beneficiary_path, updated_at = now()
         WHERE id = v_existing.id;
        INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
        VALUES (p_org, p_actor, 'mcp_server.fintech_binding_changed', 'mcp_server', p_server, p_reason,
                jsonb_build_object('tool', p_tool, 'binding', v_existing.id));
        RETURN jsonb_build_object('id', v_existing.id, 'created', false, 'changed', true);
    END IF;
    IF (SELECT count(*) FROM public.mcp_server_tool_bindings WHERE server_id = p_server) >= 50 THEN
        RETURN jsonb_build_object('created', false, 'changed', false, 'limit', true);
    END IF;
    INSERT INTO public.mcp_server_tool_bindings
        (organization_id, server_id, tool, amount_path, currency_path, fixed_currency, beneficiary_path, created_by)
    VALUES (p_org, p_server, p_tool, p_amount_path, p_currency_path, p_fixed_currency, p_beneficiary_path, p_actor)
    RETURNING id INTO v_id;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'mcp_server.fintech_binding_added', 'mcp_server', p_server, p_reason,
            jsonb_build_object('tool', p_tool, 'binding', v_id));
    RETURN jsonb_build_object('id', v_id, 'created', true, 'changed', true);
END;
$$;

-- -----------------------------------------------------------------------------
-- control_fintech_binding_remove(): unbinds one tool. The organization's LAST binding cannot be removed while it is enforcing (enforce would
-- then judge nothing while looking switched on): the caller must switch the mode first.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.control_fintech_binding_remove(p_org uuid, p_actor uuid, p_server uuid, p_binding uuid, p_reason text)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_org public.organizations%ROWTYPE;
    v_tool text;
BEGIN
    IF p_reason IS NOT NULL AND char_length(p_reason) > 300 THEN
        RAISE EXCEPTION 'the reason is at most 300 characters' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT * INTO v_org FROM public.organizations WHERE id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'organization not found' USING ERRCODE = 'no_data_found';
    END IF;
    SELECT tool INTO v_tool FROM public.mcp_server_tool_bindings WHERE id = p_binding AND server_id = p_server AND organization_id = p_org;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'binding not found' USING ERRCODE = 'no_data_found';
    END IF;
    IF v_org.fintech_shield_mode = 'enforce' AND (SELECT count(*) FROM public.mcp_server_tool_bindings WHERE organization_id = p_org) <= 1 THEN
        RETURN jsonb_build_object('removed', false, 'last_binding_in_enforce', true);
    END IF;
    DELETE FROM public.mcp_server_tool_bindings WHERE id = p_binding;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'mcp_server.fintech_binding_removed', 'mcp_server', p_server, p_reason,
            jsonb_build_object('tool', v_tool, 'binding', p_binding));
    RETURN jsonb_build_object('removed', true);
END;
$$;

REVOKE EXECUTE ON FUNCTION public.fintech_settings(uuid) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_fintech_settings(uuid, uuid, text, text, date[], text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_fintech_binding_upsert(uuid, uuid, uuid, text, text, text, text, text, text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_fintech_binding_remove(uuid, uuid, uuid, uuid, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.fintech_settings(uuid) TO service_role;
GRANT EXECUTE ON FUNCTION public.control_fintech_settings(uuid, uuid, text, text, date[], text) TO service_role;
GRANT EXECUTE ON FUNCTION public.control_fintech_binding_upsert(uuid, uuid, uuid, text, text, text, text, text, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.control_fintech_binding_remove(uuid, uuid, uuid, uuid, text) TO service_role;

COMMIT;
