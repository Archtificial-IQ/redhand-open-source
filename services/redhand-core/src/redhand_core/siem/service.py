"""Enterprise SIEM connectors, durable OCSF outbox delivery, and STIX/TAXII 2.1 polling."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import logging
from typing import Any
from uuid import UUID, uuid4

from fastapi import HTTPException, status

from redhand_core.auth.operator import OperatorContext
from redhand_core.net import outbound
from redhand_core.security.vault import SecretVaultError, decrypt_secret, encrypt_secret, mask_secret
from redhand_core.services.safe_log import safe_host
from redhand_core.siem.models import (
    ConnectorType,
    OutboxSummaryView,
    SiemConnectorCreate,
    SiemConnectorView,
    SiemOverviewResponse,
    SiemTestResult,
    TaxiiSyncResult,
    ThreatFeedCreate,
    ThreatFeedView,
    ThreatIndicatorView,
)
from redhand_core.siem.ocsf import extract_stix_indicators, to_ocsf_v110

logger = logging.getLogger("redhand.core.siem")
_MAX_OUTBOX_ATTEMPTS = 5


def _as_uuid(raw: Any) -> UUID:
    return raw if isinstance(raw, UUID) else UUID(str(raw))


def _connector_headers(connector_type: ConnectorType, token: str) -> dict[str, str]:
    if connector_type == "splunk_hec":
        return {"Authorization": f"Splunk {token}", "Content-Type": "application/json"}
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


async def get_overview(supabase: Any, organization_id: UUID) -> SiemOverviewResponse:
    org = str(organization_id)
    try:
        conn_res = await (
            supabase.table("siem_connectors")
            .select("*")
            .eq("organization_id", org)
            .order("created_at", desc=True)
            .execute()
        )
        feed_res = await (
            supabase.table("threat_intel_feeds")
            .select("*")
            .eq("organization_id", org)
            .order("created_at", desc=True)
            .execute()
        )
        ind_res = await (
            supabase.table("threat_intel_indicators")
            .select("*")
            .eq("organization_id", org)
            .order("created_at", desc=True)
            .limit(100)
            .execute()
        )
        box_res = await (
            supabase.table("siem_outbox")
            .select("status")
            .eq("organization_id", org)
            .execute()
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed reading SIEM overview: %s", type(exc).__name__)
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "SIEM & Threat Intel configuration unavailable."
        ) from None

    connectors = [
        SiemConnectorView(
            id=_as_uuid(r["id"]),
            connector_type=r["connector_type"],
            name=str(r["name"]),
            endpoint_url=str(r["endpoint_url"]),
            token_hint=str(r.get("token_hint") or "••••"),
            enabled=bool(r.get("enabled", True)),
            last_shipped_at=str(r["last_shipped_at"]) if r.get("last_shipped_at") else None,
            last_error=str(r["last_error"]) if r.get("last_error") else None,
            created_at=str(r["created_at"]) if r.get("created_at") else None,
        )
        for r in (conn_res.data or [])
    ]
    feeds = [
        ThreatFeedView(
            id=_as_uuid(r["id"]),
            name=str(r["name"]),
            collection_url=str(r["collection_url"]),
            token_hint=str(r["token_hint"]) if r.get("token_hint") else None,
            poll_interval_minutes=int(r.get("poll_interval_minutes") or 5),
            enabled=bool(r.get("enabled", True)),
            last_synced_at=str(r["last_synced_at"]) if r.get("last_synced_at") else None,
            last_indicator_count=int(r.get("last_indicator_count") or 0),
            last_error=str(r["last_error"]) if r.get("last_error") else None,
            created_at=str(r["created_at"]) if r.get("created_at") else None,
        )
        for r in (feed_res.data or [])
    ]
    indicators = [
        ThreatIndicatorView(
            id=_as_uuid(r["id"]),
            feed_id=_as_uuid(r["feed_id"]),
            indicator_type=r["indicator_type"],
            indicator_value=str(r["indicator_value"]),
            confidence=int(r.get("confidence") or 80),
            stix_id=str(r.get("stix_id") or ""),
            created_at=str(r["created_at"]) if r.get("created_at") else None,
        )
        for r in (ind_res.data or [])
    ]
    counts = {"pending": 0, "delivered": 0, "dead_letter": 0}
    for row in (box_res.data or []):
        st = str(row.get("status") or "")
        if st in counts:
            counts[st] += 1
    return SiemOverviewResponse(
        connectors=connectors,
        feeds=feeds,
        indicators=indicators,
        outbox=OutboxSummaryView(**counts),
    )


async def create_connector(
    supabase: Any, operator: OperatorContext, payload: SiemConnectorCreate
) -> SiemConnectorView:
    try:
        outbound.check_url(payload.endpoint_url, allow_insecure=outbound.insecure_webhooks_allowed())
    except outbound.OutboundBlockedError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from None

    org = str(operator.organization_id)
    try:
        encrypted = encrypt_secret(payload.auth_token.strip(), aad=org)
    except SecretVaultError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from None

    row_id = str(uuid4())
    now = datetime.now(timezone.utc).isoformat()
    hint = mask_secret(payload.auth_token)
    await supabase.table("siem_connectors").insert(
        {
            "id": row_id,
            "organization_id": org,
            "connector_type": payload.connector_type,
            "name": payload.name.strip(),
            "endpoint_url": payload.endpoint_url.strip(),
            "encrypted_token": encrypted,
            "token_hint": hint,
            "enabled": True,
            "created_by": str(operator.user_id),
            "created_at": now,
            "updated_at": now,
        }
    ).execute()
    return SiemConnectorView(
        id=UUID(row_id),
        connector_type=payload.connector_type,
        name=payload.name.strip(),
        endpoint_url=payload.endpoint_url.strip(),
        token_hint=hint,
        enabled=True,
        created_at=now,
    )


async def remove_connector(
    supabase: Any, organization_id: UUID, connector_id: UUID
) -> dict[str, bool]:
    res = await (
        supabase.table("siem_connectors")
        .delete()
        .eq("id", str(connector_id))
        .eq("organization_id", str(organization_id))
        .execute()
    )
    if not res.data:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "SIEM connector not found.")
    return {"deleted": True}


async def test_connector(
    supabase: Any, organization_id: UUID, connector_id: UUID
) -> SiemTestResult:
    org = str(organization_id)
    res = await (
        supabase.table("siem_connectors")
        .select("*")
        .eq("id", str(connector_id))
        .eq("organization_id", org)
        .execute()
    )
    rows = list(res.data or [])
    if not rows:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "SIEM connector not found.")
    conn = rows[0]

    ocsf_event = to_ocsf_v110(
        organization_id=org,
        event_kind="siem.connector.test",
        summary="RedHand OCSF v1.1.0 connectivity verification event.",
    )
    outbox_id = str(uuid4())
    now = datetime.now(timezone.utc).isoformat()
    await supabase.table("siem_outbox").insert(
        {
            "id": outbox_id,
            "organization_id": org,
            "connector_id": str(connector_id),
            "event_kind": "siem.connector.test",
            "ocsf_payload": ocsf_event,
            "status": "pending",
            "attempts": 0,
            "next_attempt_at": now,
            "created_at": now,
            "updated_at": now,
        }
    ).execute()

    return await deliver_outbox_item(supabase, organization_id=organization_id, outbox_id=UUID(outbox_id), connector=conn)


async def deliver_outbox_item(
    supabase: Any,
    *,
    organization_id: UUID,
    outbox_id: UUID,
    connector: dict[str, Any],
) -> SiemTestResult:
    org = str(organization_id)
    row_res = await (
        supabase.table("siem_outbox")
        .select("*")
        .eq("id", str(outbox_id))
        .eq("organization_id", org)
        .execute()
    )
    rows = list(row_res.data or [])
    if not rows:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Outbox item not found.")
    item = rows[0]
    endpoint = str(connector["endpoint_url"])
    try:
        secret = decrypt_secret(str(connector["encrypted_token"]), aad=org)
    except SecretVaultError as exc:
        return SiemTestResult(delivered=False, status="dead_letter", detail=str(exc))

    headers = _connector_headers(connector["connector_type"], secret)
    now = datetime.now(timezone.utc)
    attempts = int(item.get("attempts") or 0) + 1
    try:
        resp = await outbound.post_json(
            endpoint,
            {"schema": "ocsf/v1.1.0", "events": [item["ocsf_payload"]]},
            allow_insecure=outbound.insecure_webhooks_allowed(),
            headers=headers,
            timeout=5.0,
        )
        resp.raise_for_status()
        await (
            supabase.table("siem_outbox")
            .update({"status": "delivered", "attempts": attempts, "delivered_at": now.isoformat(), "last_error": None})
            .eq("id", str(outbox_id))
            .execute()
        )
        await (
            supabase.table("siem_connectors")
            .update({"last_shipped_at": now.isoformat(), "last_error": None})
            .eq("id", str(connector["id"]))
            .execute()
        )
        return SiemTestResult(delivered=True, status="delivered", detail=f"Shipped OCSF v1.1.0 event to {safe_host(endpoint)}.")
    except outbound.OutboundBlockedError as exc:
        outbound.record_blocked("siem")
        msg = str(exc)
        await (
            supabase.table("siem_outbox")
            .update({"status": "dead_letter", "attempts": attempts, "last_error": msg})
            .eq("id", str(outbox_id))
            .execute()
        )
        await supabase.table("siem_connectors").update({"last_error": msg}).eq("id", str(connector["id"])).execute()
        return SiemTestResult(delivered=False, status="dead_letter", detail=msg)
    except outbound.OutboundError as exc:
        msg = str(exc)
        next_status: str = "dead_letter" if attempts >= _MAX_OUTBOX_ATTEMPTS else "pending"
        retry_at = (now + timedelta(seconds=15 * attempts)).isoformat()
        await (
            supabase.table("siem_outbox")
            .update({"status": next_status, "attempts": attempts, "next_attempt_at": retry_at, "last_error": msg})
            .eq("id", str(outbox_id))
            .execute()
        )
        await supabase.table("siem_connectors").update({"last_error": msg}).eq("id", str(connector["id"])).execute()
        return SiemTestResult(
            delivered=False,
            status="dead_letter" if next_status == "dead_letter" else "pending",
            detail=msg,
        )


async def create_feed(
    supabase: Any, operator: OperatorContext, payload: ThreatFeedCreate
) -> ThreatFeedView:
    try:
        outbound.check_url(payload.collection_url, allow_insecure=outbound.insecure_webhooks_allowed())
    except outbound.OutboundBlockedError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from None

    org = str(operator.organization_id)
    enc: str | None = None
    hint: str | None = None
    if payload.auth_token and payload.auth_token.strip():
        try:
            enc = encrypt_secret(payload.auth_token.strip(), aad=org)
        except SecretVaultError as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from None
        hint = mask_secret(payload.auth_token)

    row_id = str(uuid4())
    now = datetime.now(timezone.utc).isoformat()
    await supabase.table("threat_intel_feeds").insert(
        {
            "id": row_id,
            "organization_id": org,
            "name": payload.name.strip(),
            "collection_url": payload.collection_url.strip(),
            "encrypted_auth": enc,
            "token_hint": hint,
            "poll_interval_minutes": payload.poll_interval_minutes,
            "enabled": True,
            "last_indicator_count": 0,
            "created_by": str(operator.user_id),
            "created_at": now,
            "updated_at": now,
        }
    ).execute()
    return ThreatFeedView(
        id=UUID(row_id),
        name=payload.name.strip(),
        collection_url=payload.collection_url.strip(),
        token_hint=hint,
        poll_interval_minutes=payload.poll_interval_minutes,
        enabled=True,
        created_at=now,
    )


async def remove_feed(supabase: Any, organization_id: UUID, feed_id: UUID) -> dict[str, bool]:
    res = await (
        supabase.table("threat_intel_feeds")
        .delete()
        .eq("id", str(feed_id))
        .eq("organization_id", str(organization_id))
        .execute()
    )
    if not res.data:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Threat feed not found.")
    return {"deleted": True}


async def sync_feed(supabase: Any, organization_id: UUID, feed_id: UUID) -> TaxiiSyncResult:
    org = str(organization_id)
    res = await (
        supabase.table("threat_intel_feeds")
        .select("*")
        .eq("id", str(feed_id))
        .eq("organization_id", org)
        .execute()
    )
    rows = list(res.data or [])
    if not rows:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Threat feed not found.")
    feed = rows[0]
    url = str(feed["collection_url"])
    headers = {"Accept": "application/taxii+json;version=2.1, application/json"}
    if feed.get("encrypted_auth"):
        try:
            tok = decrypt_secret(str(feed["encrypted_auth"]), aad=org)
            headers["Authorization"] = f"Bearer {tok}"
        except SecretVaultError as exc:
            return TaxiiSyncResult(feed_id=feed_id, imported_count=0, status="failed", detail=str(exc))

    now = datetime.now(timezone.utc).isoformat()
    try:
        resp = await outbound.get_checked(
            url,
            allow_insecure=outbound.insecure_webhooks_allowed(),
            headers=headers,
            timeout=5.0,
        )
        resp.raise_for_status()
        bundle = json.loads(resp.content.decode("utf-8"))
        indicators = extract_stix_indicators(bundle if isinstance(bundle, dict) else {})
    except (outbound.OutboundError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        msg = str(exc) if isinstance(exc, outbound.OutboundError) else "Invalid STIX 2.1 bundle response."
        await supabase.table("threat_intel_feeds").update({"last_error": msg}).eq("id", str(feed_id)).execute()
        return TaxiiSyncResult(feed_id=feed_id, imported_count=0, status="failed", detail=msg)

    for ind_type, ind_val, stix_id, confidence in indicators:
        await (
            supabase.table("threat_intel_indicators")
            .upsert(
                {
                    "id": str(uuid4()),
                    "organization_id": org,
                    "feed_id": str(feed_id),
                    "indicator_type": ind_type,
                    "indicator_value": ind_val,
                    "confidence": confidence,
                    "stix_id": stix_id,
                    "created_at": now,
                },
                on_conflict="organization_id,indicator_type,indicator_value",
            )
            .execute()
        )

    await (
        supabase.table("threat_intel_feeds")
        .update({"last_synced_at": now, "last_indicator_count": len(indicators), "last_error": None})
        .eq("id", str(feed_id))
        .execute()
    )
    return TaxiiSyncResult(
        feed_id=feed_id,
        imported_count=len(indicators),
        status="synced",
        detail=f"Synced {len(indicators)} STIX indicators from {safe_host(url)}.",
    )


async def enqueue_event_for_org(
    supabase: Any,
    organization_id: UUID,
    *,
    event_kind: str,
    agent_id: str | None = None,
    severity_id: int = 4,
    summary: str = "",
) -> int:
    """Fans out an OCSF v1.1.0 record to all enabled SIEM connectors for `organization_id` and attempts delivery."""
    org = str(organization_id)
    try:
        res = await (
            supabase.table("siem_connectors")
            .select("*")
            .eq("organization_id", org)
            .eq("enabled", True)
            .execute()
        )
        connectors = list(res.data or [])
        if not connectors:
            return 0
        ocsf_event = to_ocsf_v110(
            organization_id=org,
            event_kind=event_kind,
            agent_id=agent_id,
            severity_id=severity_id,
            summary=summary,
        )
        now = datetime.now(timezone.utc).isoformat()
        enqueued = 0
        for conn in connectors:
            outbox_id = str(uuid4())
            await supabase.table("siem_outbox").insert(
                {
                    "id": outbox_id,
                    "organization_id": org,
                    "connector_id": str(conn["id"]),
                    "event_kind": event_kind,
                    "ocsf_payload": ocsf_event,
                    "status": "pending",
                    "attempts": 0,
                    "next_attempt_at": now,
                    "created_at": now,
                    "updated_at": now,
                }
            ).execute()
            await deliver_outbox_item(supabase, organization_id=organization_id, outbox_id=UUID(outbox_id), connector=conn)
            enqueued += 1
        return enqueued
    except Exception as exc:  # noqa: BLE001 - background shipping must never crash event ingest
        logger.warning("SIEM background enqueue error: %s", type(exc).__name__)
        return 0


async def drain_pending_outbox(supabase: Any, limit: int = 25) -> int:
    """Retries due pending OCSF outbox items off the critical path."""
    now = datetime.now(timezone.utc)
    processed = 0
    try:
        res = await supabase.table("siem_outbox").select("*").eq("status", "pending").limit(limit).execute()
        for item in res.data or []:
            next_at_raw = item.get("next_attempt_at")
            if next_at_raw:
                try:
                    next_at = datetime.fromisoformat(str(next_at_raw).replace("Z", "+00:00"))
                    if next_at > now:
                        continue
                except ValueError:
                    pass
            conn_res = await (
                supabase.table("siem_connectors")
                .select("*")
                .eq("id", str(item["connector_id"]))
                .eq("organization_id", str(item["organization_id"]))
                .execute()
            )
            conns = list(conn_res.data or [])
            if not conns or not bool(conns[0].get("enabled", True)):
                continue
            await deliver_outbox_item(
                supabase,
                organization_id=_as_uuid(item["organization_id"]),
                outbox_id=_as_uuid(item["id"]),
                connector=conns[0],
            )
            processed += 1
    except Exception as exc:  # noqa: BLE001
        logger.warning("Outbox sweeper error: %s", type(exc).__name__)
    return processed


async def poll_due_feeds(supabase: Any) -> int:
    """Polls any enabled STIX/TAXII 2.1 feed whose cadence interval has elapsed."""
    now = datetime.now(timezone.utc)
    synced = 0
    try:
        res = await supabase.table("threat_intel_feeds").select("*").eq("enabled", True).limit(20).execute()
        for feed in res.data or []:
            last_raw = feed.get("last_synced_at")
            interval_min = int(feed.get("poll_interval_minutes") or 5)
            if last_raw:
                try:
                    last_dt = datetime.fromisoformat(str(last_raw).replace("Z", "+00:00"))
                    if last_dt + timedelta(minutes=interval_min) > now:
                        continue
                except ValueError:
                    pass
            await sync_feed(supabase, _as_uuid(feed["organization_id"]), _as_uuid(feed["id"]))
            synced += 1
    except Exception as exc:  # noqa: BLE001
        logger.warning("TAXII sweeper error: %s", type(exc).__name__)
    return synced
