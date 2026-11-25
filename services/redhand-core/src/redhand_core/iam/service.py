"""Persistence & authorization service for Ephemeral IAM Broker policies and audit logs."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from fastapi import HTTPException, status

from redhand_core.auth.operator import OperatorContext
from redhand_core.iam.models import (
    CloudConnectionCreate,
    CloudConnectionView,
    IamMintEventView,
    IamOverviewResponse,
    IamPolicyCreate,
    IamPolicyView,
    IamProvider,
)

logger = logging.getLogger("redhand.core.iam")


def _as_uuid(raw: Any) -> UUID:
    return raw if isinstance(raw, UUID) else UUID(str(raw))


async def get_overview(supabase: Any, organization_id: UUID) -> IamOverviewResponse:
    org = str(organization_id)
    try:
        conns_res = await (
            supabase.table("iam_cloud_connections")
            .select("*")
            .eq("organization_id", org)
            .order("created_at", desc=True)
            .execute()
        )
        pol_res = await (
            supabase.table("iam_broker_policies")
            .select("*")
            .eq("organization_id", org)
            .order("created_at", desc=True)
            .execute()
        )
        mints_res = await (
            supabase.table("iam_mint_events")
            .select("*")
            .eq("organization_id", org)
            .order("created_at", desc=True)
            .limit(50)
            .execute()
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed reading IAM overview: %s", type(exc).__name__)
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "Ephemeral IAM configuration could not be read."
        ) from None

    connections = [
        CloudConnectionView(
            id=_as_uuid(r["id"]),
            provider=r["provider"],
            display_name=str(r["display_name"]),
            principal_identifier=str(r["principal_identifier"]),
            region_or_project=str(r.get("region_or_project") or "global"),
            status=str(r.get("status") or "verified"),
            created_at=str(r["created_at"]) if r.get("created_at") else None,
        )
        for r in (conns_res.data or [])
    ]
    policies = [
        IamPolicyView(
            id=_as_uuid(r["id"]),
            external_agent_id=str(r["external_agent_id"]),
            tool_name=str(r["tool_name"]),
            provider=r["provider"],
            target_principal=str(r["target_principal"]),
            target_resource=str(r["target_resource"]),
            allowed_actions=[str(a) for a in (r.get("allowed_actions") or [])],
            ttl_seconds=int(r.get("ttl_seconds") or 60),
            enabled=bool(r.get("enabled", True)),
            created_at=str(r["created_at"]) if r.get("created_at") else None,
        )
        for r in (pol_res.data or [])
    ]
    mints = [
        IamMintEventView(
            id=_as_uuid(r["id"]),
            external_agent_id=str(r["external_agent_id"]),
            tool_name=str(r["tool_name"]),
            provider=r["provider"],
            token_jti=str(r["token_jti"]),
            trace_id=str(r["trace_id"]),
            span_id=str(r["span_id"]),
            outcome=r["outcome"],
            detail=str(r["detail"]) if r.get("detail") else None,
            expires_at=str(r["expires_at"]) if r.get("expires_at") else None,
            mint_latency_ms=float(r.get("mint_latency_ms") or 0.0),
            created_at=str(r["created_at"]) if r.get("created_at") else None,
        )
        for r in (mints_res.data or [])
    ]
    return IamOverviewResponse(connections=connections, policies=policies, recent_mints=mints)


async def create_connection(
    supabase: Any, operator: OperatorContext, payload: CloudConnectionCreate
) -> CloudConnectionView:
    row_id = str(uuid4())
    now = datetime.now(timezone.utc).isoformat()
    row = {
        "id": row_id,
        "organization_id": str(operator.organization_id),
        "provider": payload.provider,
        "display_name": payload.display_name,
        "principal_identifier": payload.principal_identifier,
        "region_or_project": payload.region_or_project,
        "status": "verified",
        "created_by": str(operator.user_id),
        "created_at": now,
        "updated_at": now,
    }
    await supabase.table("iam_cloud_connections").insert(row).execute()
    return CloudConnectionView(
        id=UUID(row_id),
        provider=payload.provider,
        display_name=payload.display_name,
        principal_identifier=payload.principal_identifier,
        region_or_project=payload.region_or_project,
        status="verified",
        created_at=now,
    )


async def remove_connection(
    supabase: Any, organization_id: UUID, connection_id: UUID
) -> dict[str, bool]:
    res = await (
        supabase.table("iam_cloud_connections")
        .delete()
        .eq("id", str(connection_id))
        .eq("organization_id", str(organization_id))
        .execute()
    )
    if not res.data:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Cloud connection not found.")
    return {"deleted": True}


async def create_policy(
    supabase: Any, operator: OperatorContext, payload: IamPolicyCreate
) -> IamPolicyView:
    row_id = str(uuid4())
    now = datetime.now(timezone.utc).isoformat()
    row = {
        "id": row_id,
        "organization_id": str(operator.organization_id),
        "external_agent_id": payload.external_agent_id,
        "tool_name": payload.tool_name,
        "provider": payload.provider,
        "target_principal": payload.target_principal,
        "target_resource": payload.target_resource,
        "allowed_actions": payload.allowed_actions,
        "ttl_seconds": payload.ttl_seconds,
        "enabled": True,
        "created_by": str(operator.user_id),
        "created_at": now,
        "updated_at": now,
    }
    await (
        supabase.table("iam_broker_policies")
        .upsert(row, on_conflict="organization_id,external_agent_id,tool_name,provider")
        .execute()
    )
    return IamPolicyView(
        id=UUID(row_id),
        external_agent_id=payload.external_agent_id,
        tool_name=payload.tool_name,
        provider=payload.provider,
        target_principal=payload.target_principal,
        target_resource=payload.target_resource,
        allowed_actions=payload.allowed_actions,
        ttl_seconds=payload.ttl_seconds,
        enabled=True,
        created_at=now,
    )


async def remove_policy(supabase: Any, organization_id: UUID, policy_id: UUID) -> dict[str, bool]:
    res = await (
        supabase.table("iam_broker_policies")
        .delete()
        .eq("id", str(policy_id))
        .eq("organization_id", str(organization_id))
        .execute()
    )
    if not res.data:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "IAM broker policy not found.")
    return {"deleted": True}


async def check_policy_boundary(
    supabase: Any,
    *,
    organization_id: UUID,
    external_agent_id: str,
    tool_name: str,
    provider: IamProvider,
    requested_actions: list[str],
    target_resource: str,
) -> None:
    """Enforces org IAM broker policy when configured for this (agent, tool, provider)."""
    try:
        res = await (
            supabase.table("iam_broker_policies")
            .select("*")
            .eq("organization_id", str(organization_id))
            .eq("external_agent_id", external_agent_id)
            .eq("tool_name", tool_name)
            .eq("provider", provider)
            .execute()
        )
    except Exception:  # noqa: BLE001 - fail closed if policy table read errors
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "IAM policy check unavailable.") from None

    rows = list(res.data or [])
    if not rows:
        return  # No custom broker restriction beyond passport tool scope

    policy = rows[0]
    if not bool(policy.get("enabled", True)):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "IAM broker policy for this tool is disabled.")
    policy_res = str(policy.get("target_resource") or "")
    if policy_res and target_resource != policy_res and not target_resource.startswith(policy_res.rstrip("*")):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Requested resource exceeds the downscoped IAM policy boundary.",
        )
    allowed = {str(a) for a in (policy.get("allowed_actions") or [])}
    if allowed and not set(requested_actions).issubset(allowed):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Requested cloud permissions exceed the configured IAM policy.",
        )


async def record_mint_event(
    supabase: Any,
    *,
    organization_id: UUID,
    external_agent_id: str,
    tool_name: str,
    provider: IamProvider,
    token_jti: str,
    trace_id: str,
    span_id: str,
    outcome: str,
    detail: str | None = None,
    expires_at: str | None = None,
    mint_latency_ms: float = 0.0,
) -> None:
    """Best-effort append to iam_mint_events for live dashboard visibility."""
    try:
        await supabase.table("iam_mint_events").insert(
            {
                "id": str(uuid4()),
                "organization_id": str(organization_id),
                "external_agent_id": external_agent_id,
                "tool_name": tool_name,
                "provider": provider,
                "token_jti": token_jti,
                "trace_id": trace_id,
                "span_id": span_id,
                "outcome": outcome,
                "detail": detail,
                "expires_at": expires_at,
                "mint_latency_ms": mint_latency_ms,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        ).execute()
    except Exception as exc:  # noqa: BLE001 - never crash mint path on secondary log write
        logger.warning("Failed recording IAM mint event: %s", type(exc).__name__)
