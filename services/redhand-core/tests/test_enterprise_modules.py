"""
Unit & integration tests for Phase 1-3 Enterprise modules:
- Secret Envelope Vault (AES-256-GCM + tenant AAD binding + fail-closed prod)
- Ephemeral IAM Broker (connections, policies, boundary checks, mint log)
- SIEM & Threat Intel (OCSF v1.1.0, STIX 2.1 extraction, SSRF guard, outbox)
- Async Cyber-Model Escalation (pre-egress scrubbing, BYOK dispatch, circuit breaker)
"""

from __future__ import annotations

import base64
import json
import os
from uuid import UUID, uuid4

import pytest
from fastapi import HTTPException

from redhand_core.auth.operator import OperatorContext
from redhand_core.config import get_settings
from redhand_core.escalation import service as escalation_service
from redhand_core.escalation.models import EscalationEvaluateRequest, EscalationPolicyCreate
from redhand_core.iam import service as iam_service
from redhand_core.iam.models import CloudConnectionCreate, IamPolicyCreate
from redhand_core.net import outbound
from redhand_core.security.vault import SecretVaultError, decrypt_secret, encrypt_secret, mask_secret
from redhand_core.services.local_store import DEFAULT_ORG_ID, DEV_OPERATORS, LocalSupabaseAdapter
from redhand_core.siem import service as siem_service
from redhand_core.siem.models import SiemConnectorCreate, ThreatFeedCreate
from redhand_core.siem.ocsf import extract_stix_indicators, to_ocsf_v110


def _admin() -> OperatorContext:
    return OperatorContext(
        user_id=UUID(DEV_OPERATORS["admin"]["id"]),
        organization_id=UUID(DEFAULT_ORG_ID),
        role="admin",
        email="admin@dev.local",
    )


def test_secret_vault_roundtrip_aad_isolation_and_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    key_b64 = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
    monkeypatch.setenv("ENTERPRISE_SECRETS_KEY", key_b64)
    get_settings.cache_clear()
    sample_secret = "sk" + "-ant-test-envelope-token-1234"
    try:
        token = encrypt_secret(sample_secret, aad=DEFAULT_ORG_ID)
        assert token.startswith("v1:")
        assert "envelope-token" not in token
        assert decrypt_secret(token, aad=DEFAULT_ORG_ID) == sample_secret
        assert mask_secret(sample_secret) == "••••1234"
        with pytest.raises(SecretVaultError):
            decrypt_secret(token, aad=str(uuid4()))

        # Production without ENTERPRISE_SECRETS_KEY must fail closed
        monkeypatch.delenv("ENTERPRISE_SECRETS_KEY")
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("OPERATOR_JWKS_URL", "https://example.supabase.co/auth/v1/.well-known/jwks.json")
        monkeypatch.setenv("OPERATOR_JWT_ISSUER", "https://example.supabase.co/auth/v1")
        get_settings.cache_clear()
        with pytest.raises(SecretVaultError):
            encrypt_secret("secret", aad=DEFAULT_ORG_ID)
    finally:
        monkeypatch.delenv("OPERATOR_JWKS_URL", raising=False)
        monkeypatch.delenv("OPERATOR_JWT_ISSUER", raising=False)
        monkeypatch.delenv("ENVIRONMENT", raising=False)
        monkeypatch.delenv("ENTERPRISE_SECRETS_KEY", raising=False)
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_ephemeral_iam_crud_boundary_and_tenant_isolation() -> None:
    store = LocalSupabaseAdapter()
    op = _admin()

    conn = await iam_service.create_connection(
        store,
        op,
        CloudConnectionCreate(
            provider="aws_sts",
            display_name="Prod Read Role",
            principal_identifier="arn:aws:iam::123456789012:role/redhand-ro",
            region_or_project="ap-southeast-1",
        ),
    )
    pol = await iam_service.create_policy(
        store,
        op,
        IamPolicyCreate(
            external_agent_id="finops-cloudsql-remediator",
            tool_name="query_cloud_billing_export",
            provider="gcp_sts",
            target_principal="sa-finops@prod.iam.gserviceaccount.com",
            target_resource="//bigquery.googleapis.com/projects/prod/datasets/billing",
            allowed_actions=["bigquery.tables.getData"],
            ttl_seconds=45,
        ),
    )

    # Boundary passes for exact resource & action
    await iam_service.check_policy_boundary(
        store,
        organization_id=op.organization_id,
        external_agent_id="finops-cloudsql-remediator",
        tool_name="query_cloud_billing_export",
        provider="gcp_sts",
        requested_actions=["bigquery.tables.getData"],
        target_resource="//bigquery.googleapis.com/projects/prod/datasets/billing",
    )

    # Disallowed action or broader resource refuses fail-closed
    with pytest.raises(HTTPException) as exc:
        await iam_service.check_policy_boundary(
            store,
            organization_id=op.organization_id,
            external_agent_id="finops-cloudsql-remediator",
            tool_name="query_cloud_billing_export",
            provider="gcp_sts",
            requested_actions=["storage.objects.delete"],
            target_resource="//bigquery.googleapis.com/projects/prod/datasets/billing",
        )
    assert exc.value.status_code == 403

    await iam_service.record_mint_event(
        store,
        organization_id=op.organization_id,
        external_agent_id="finops-cloudsql-remediator",
        tool_name="query_cloud_billing_export",
        provider="gcp_sts",
        token_jti="rh_jti_test_1",
        trace_id="t" * 32,
        span_id="s" * 16,
        outcome="minted",
        mint_latency_ms=4.2,
    )

    overview = await iam_service.get_overview(store, op.organization_id)
    assert len(overview.connections) == 1
    assert len(overview.policies) == 1
    assert len(overview.recent_mints) == 1
    assert overview.microsoft_entra_status == "coming_soon"

    # Cross-tenant delete returns 404
    with pytest.raises(HTTPException) as not_found:
        await iam_service.remove_connection(store, uuid4(), conn.id)
    assert not_found.value.status_code == 404

    assert await iam_service.remove_policy(store, op.organization_id, pol.id) == {"deleted": True}
    assert await iam_service.remove_connection(store, op.organization_id, conn.id) == {"deleted": True}


@pytest.mark.asyncio
async def test_siem_ocsf_connector_ssrf_and_taxii_sync(monkeypatch: pytest.MonkeyPatch) -> None:
    store = LocalSupabaseAdapter()
    op = _admin()

    # SSRF private metadata URL refused at creation
    with pytest.raises(HTTPException) as blocked:
        await siem_service.create_connector(
            store,
            op,
            SiemConnectorCreate(
                connector_type="splunk_hec",
                name="Bad SSRF Connector",
                endpoint_url="https://169.254.169.254/services/collector",
                auth_token="hec-secret-token-1234",
            ),
        )
    assert blocked.value.status_code == 422

    conn = await siem_service.create_connector(
        store,
        op,
        SiemConnectorCreate(
            connector_type="splunk_hec",
            name="Splunk Prod",
            endpoint_url="https://splunk.example.com/services/collector",
            auth_token="hec-secret-token-1234",
        ),
    )
    assert conn.token_hint == "••••1234"

    posted: list[dict[str, object]] = []

    async def fake_post(url: str, payload: object, **kwargs: object) -> outbound.OutboundResponse:
        posted.append({"url": url, "payload": payload, "headers": kwargs.get("headers")})
        return outbound.OutboundResponse(200, b'{"text":"Success","code":0}')

    monkeypatch.setattr(outbound, "post_json", fake_post)
    test_res = await siem_service.test_connector(store, op.organization_id, conn.id)
    assert test_res.delivered is True
    assert posted[0]["payload"]["schema"] == "ocsf/v1.1.0"  # type: ignore[index]

    ocsf = to_ocsf_v110(organization_id=DEFAULT_ORG_ID, event_kind="honeytoken.tripped", severity_id=5)
    assert ocsf["class_uid"] == 2004
    assert ocsf["metadata"]["version"] == "1.1.0"

    feed = await siem_service.create_feed(
        store,
        op,
        ThreatFeedCreate(name="RedHand STIX Feed", collection_url="https://taxii.example.com/objects/"),
    )

    stix_bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--1111",
                "pattern": "[domain-name:value = 'exfil-c2.evil.example']",
                "confidence": 95,
            },
            {
                "type": "indicator",
                "id": "indicator--2222",
                "pattern": "[ipv4-addr:value = '198.51.100.42']",
                "confidence": 90,
            },
        ],
    }
    assert len(extract_stix_indicators(stix_bundle)) == 2

    async def fake_get(url: str, **kwargs: object) -> outbound.OutboundResponse:
        return outbound.OutboundResponse(200, json.dumps(stix_bundle).encode("utf-8"))

    monkeypatch.setattr(outbound, "get_checked", fake_get)
    sync = await siem_service.sync_feed(store, op.organization_id, feed.id)
    assert sync.status == "synced"
    assert sync.imported_count == 2

    overview = await siem_service.get_overview(store, op.organization_id)
    assert overview.outbox.delivered == 1
    assert len(overview.indicators) == 2


@pytest.mark.asyncio
async def test_cyber_escalation_scrubs_secrets_and_freezes_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    store = LocalSupabaseAdapter()
    op = _admin()

    # Verify scrubbing strips every major credential pattern before egress
    fake_ant = "sk" + "-ant-api03-1234567890abcdef123456"
    fake_google = "AIza" + "SyA1234567890abcdefghijklmnopqrstuv"
    fake_gh = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
    raw_trace = f"Agent tried {fake_ant} and {fake_google} with {fake_gh}"
    redacted = escalation_service.redact_trace_for_model(raw_trace)
    assert "sk-ant-" not in redacted
    assert "AIza" not in redacted
    assert "ghp_" not in redacted
    assert "[REDACTED_ANTHROPIC_KEY]" in redacted
    assert "[REDACTED_GOOGLE_KEY]" in redacted
    assert "[REDACTED_GITHUB_TOKEN]" in redacted

    byok_key = "sk" + "-ant-customer-byok-key-9876"
    await escalation_service.create_policy(
        store,
        op,
        EscalationPolicyCreate(
            name="Multi-Turn Exfil",
            trigger_kind="onnx_borderline",
            threshold_value=0.55,
            provider="anthropic",
            endpoint_url="https://api.anthropic.com/v1/messages",
            model_name="claude-3-7-sonnet",
            api_key=byok_key,
            circuit_breaker_action="freeze_agent",
        ),
    )

    async def fake_model(url: str, payload: object, **kwargs: object) -> outbound.OutboundResponse:
        return outbound.OutboundResponse(
            200,
            json.dumps(
                {
                    "content": [
                        {
                            "text": json.dumps(
                                {
                                    "verdict": "malicious",
                                    "confidence": 0.94,
                                    "reasoning": "Multi-step exfiltration detected.",
                                }
                            )
                        }
                    ]
                }
            ).encode("utf-8"),
        )

    monkeypatch.setattr(outbound, "post_json", fake_model)
    job = await escalation_service.evaluate_trace(
        store,
        op.organization_id,
        EscalationEvaluateRequest(
            external_agent_id="finops-cloudsql-remediator",
            trigger_kind="onnx_borderline",
            signal_score=0.72,
            delegation_depth=2,
            trace_excerpt=raw_trace,
        ),
    )
    assert job.status == "completed"
    assert job.verdict == "malicious"
    assert job.action_taken == "agent_frozen"
    assert "AIza" not in job.redacted_trace

    agent = next(a for a in store.tables["agents"] if a["external_agent_id"] == "finops-cloudsql-remediator")
    assert agent["status"] == "frozen"


@pytest.mark.asyncio
async def test_managed_cyber_model_gemini_fenced_reply_and_sweeper_and_ioc_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agentwall.src.firewall.destinations import blocked_hits, scan_arguments

    store = LocalSupabaseAdapter()
    op = _admin()

    # 1. TAXII IOC cache blocking in AgentWall (<2ms pure scan; coarse_host returns apex)
    scan = scan_arguments({"url": "https://exfil-c2.evil.example/drop?k=1"})
    hits = blocked_hits(scan, frozenset({"exfil-c2.evil.example"}))
    assert hits == ("evil.example",)

    # 2. Managed RedHand policy without CYBER_MODEL_API_KEY fails closed on evaluate
    await escalation_service.create_policy(
        store,
        op,
        EscalationPolicyCreate(
            name="Managed Gemini Demo",
            trigger_kind="onnx_borderline",
            threshold_value=0.5,
            provider="managed_redhand",
            circuit_breaker_action="safe_mode",
        ),
    )

    monkeypatch.setenv("CYBER_MODEL_PROVIDER", "gemini_vertex")
    monkeypatch.setenv("CYBER_MODEL_NAME", "gemini-2.5-flash")
    monkeypatch.setenv("CYBER_MODEL_API_KEY", "AIza" + "DemoManagedTestKey012345678901234")
    get_settings.cache_clear()
    try:
        async def fake_gemini(url: str, payload: object, **kwargs: object) -> outbound.OutboundResponse:
            return outbound.OutboundResponse(
                200,
                json.dumps(
                    {
                        "candidates": [
                            {
                                "content": {
                                    "parts": [
                                        {
                                            "text": "```json\n"
                                            + json.dumps(
                                                {
                                                    "verdict": "malicious",
                                                    "confidence": 0.91,
                                                    "reasoning": "Exfiltration pattern matched.",
                                                }
                                            )
                                            + "\n```"
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                ).encode("utf-8"),
            )

        monkeypatch.setattr(outbound, "post_json", fake_gemini)
        job = await escalation_service.evaluate_trace(
            store,
            op.organization_id,
            EscalationEvaluateRequest(
                external_agent_id="rag-secops-triager",
                trigger_kind="onnx_borderline",
                signal_score=0.80,
                delegation_depth=1,
                trace_excerpt="Attempted outbound post",
            ),
        )
        assert job.status == "completed"
        assert job.verdict == "malicious"
        assert job.action_taken == "org_safe_mode_enabled"
    finally:
        monkeypatch.delenv("CYBER_MODEL_API_KEY", raising=False)
        monkeypatch.delenv("CYBER_MODEL_NAME", raising=False)
        monkeypatch.delenv("CYBER_MODEL_PROVIDER", raising=False)
        get_settings.cache_clear()

    # 3. Background SIEM fanout + retry drain
    await siem_service.create_connector(
        store,
        op,
        SiemConnectorCreate(
            connector_type="splunk_hec",
            name="Webhook Demo",
            endpoint_url="https://webhook.site/demo-endpoint",
            auth_token="demo-token-123456",
        ),
    )

    async def fake_siem_post(url: str, payload: object, **kwargs: object) -> outbound.OutboundResponse:
        return outbound.OutboundResponse(200, b"ok")

    monkeypatch.setattr(outbound, "post_json", fake_siem_post)
    sent = await siem_service.enqueue_event_for_org(
        store,
        op.organization_id,
        event_kind="gateway.tool.blocked",
        agent_id="rag-secops-triager",
        summary="Blocked destructive tool",
    )
    assert sent == 1
    assert await siem_service.drain_pending_outbox(store) == 0
