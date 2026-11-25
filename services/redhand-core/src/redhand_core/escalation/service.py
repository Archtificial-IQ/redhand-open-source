"""
Async Deep Cyber-Model Escalation service:
1. Stores BYOK frontier model endpoints with AES-256-GCM envelope encryption.
2. Scrubs secrets/tokens from agent traces BEFORE egress.
3. Dispatches suspicious traces off-path via `outbound.post_json` and triggers
   automated circuit-breaker actions (agent freeze / org Safe Mode) on confirmation.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import re
import time
from typing import Any
from uuid import UUID, uuid4

from fastapi import HTTPException, status

from redhand_core.auth.operator import OperatorContext
from redhand_core.escalation.models import (
    EscalationEvaluateRequest,
    EscalationJobView,
    EscalationOverviewResponse,
    EscalationPolicyCreate,
    EscalationPolicyView,
    ModelProvider,
)
from redhand_core.net import outbound
from redhand_core.security.vault import SecretVaultError, decrypt_secret, encrypt_secret, mask_secret

logger = logging.getLogger("redhand.core.escalation")

_SCRUB_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"sk-ant-[a-zA-Z0-9_-]{12,}"), "[REDACTED_ANTHROPIC_KEY]"),
    (re.compile(r"sk-[a-zA-Z0-9_-]{16,}"), "[REDACTED_OPENAI_KEY]"),
    (re.compile(r"AIza[0-9A-Za-z_-]{20,}"), "[REDACTED_GOOGLE_KEY]"),
    (re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{20,}|github_pat_[0-9A-Za-z_]{20,}"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"(?:A3T[A-Z0-9]|AKIA)[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"ya29\.[0-9a-zA-Z_.-]{16,}"), "[REDACTED_GCP_BEARER]"),
    (re.compile(r"Bearer\s+[A-Za-z0-9._-]{16,}", re.IGNORECASE), "Bearer [REDACTED_TOKEN]"),
)


def _as_uuid(raw: Any) -> UUID:
    return raw if isinstance(raw, UUID) else UUID(str(raw))


def redact_trace_for_model(text: str) -> str:
    """Strips credential patterns before storing or sending any trace to an external model."""
    cleaned = text
    for pattern, repl in _SCRUB_PATTERNS:
        cleaned = pattern.sub(repl, cleaned)
    return cleaned[:4000]


def _provider_headers(provider: ModelProvider, api_key: str) -> dict[str, str]:
    if provider == "anthropic":
        return {"x-api-key": api_key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"}
    if provider == "gemini_vertex":
        return {"x-goog-api-key": api_key, "Content-Type": "application/json"}
    return {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}


def _provider_payload(provider: ModelProvider, model_name: str, redacted_trace: str, trigger_kind: str) -> dict[str, Any]:
    prompt = (
        "Classify whether the following scrubbed AI-agent MCP trace shows prompt injection, "
        "data exfiltration, or unauthorized tool escalation. Reply strictly as JSON with keys "
        '{"verdict":"malicious|benign|inconclusive","confidence":0.0..1.0,"reasoning":"short"}.\n'
        f"Trigger: {trigger_kind}\nTrace:\n{redacted_trace}"
    )
    if provider == "anthropic":
        return {
            "model": model_name,
            "max_tokens": 256,
            "messages": [{"role": "user", "content": prompt}],
        }
    if provider == "gemini_vertex":
        return {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.0, "maxOutputTokens": 256},
        }
    return {
        "model": model_name,
        "temperature": 0.0,
        "max_tokens": 256,
        "messages": [{"role": "user", "content": prompt}],
    }


def _strip_json_fences(raw: str) -> str:
    txt = raw.strip()
    if txt.startswith("```"):
        lines = txt.splitlines()
        if len(lines) >= 2 and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        txt = "\n".join(lines).strip()
    return txt


def _parse_verdict(body: bytes) -> tuple[str, float, str]:
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ("inconclusive", 0.0, "Non-JSON response from cyber-model endpoint.")
    if isinstance(data, dict) and data.get("verdict") in ("malicious", "benign", "inconclusive"):
        conf = float(data.get("confidence") or 0.0)
        return (str(data["verdict"]), max(0.0, min(1.0, conf)), str(data.get("reasoning") or "")[:240])
    # Extract JSON object from OpenAI/Anthropic/Gemini text envelopes if wrapped
    text_candidates: list[str] = []
    if isinstance(data, dict):
        for choice in data.get("choices") or []:
            if isinstance(choice, dict) and isinstance(choice.get("message"), dict):
                text_candidates.append(str(choice["message"].get("content") or ""))
        for item in data.get("content") or []:
            if isinstance(item, dict) and item.get("text"):
                text_candidates.append(str(item["text"]))
        for cand in data.get("candidates") or []:
            if isinstance(cand, dict):
                parts = (cand.get("content") or {}).get("parts") or []
                for p in parts:
                    if isinstance(p, dict) and p.get("text"):
                        text_candidates.append(str(p["text"]))
    for txt in text_candidates:
        try:
            inner = json.loads(_strip_json_fences(txt))
            if isinstance(inner, dict) and inner.get("verdict") in ("malicious", "benign", "inconclusive"):
                conf = float(inner.get("confidence") or 0.0)
                return (str(inner["verdict"]), max(0.0, min(1.0, conf)), str(inner.get("reasoning") or "")[:240])
        except json.JSONDecodeError:
            continue
    return ("inconclusive", 0.0, "Endpoint replied without structured verdict JSON.")


async def get_overview(supabase: Any, organization_id: UUID) -> EscalationOverviewResponse:
    org = str(organization_id)
    try:
        pol_res = await (
            supabase.table("escalation_policies")
            .select("*")
            .eq("organization_id", org)
            .order("created_at", desc=True)
            .execute()
        )
        job_res = await (
            supabase.table("escalation_jobs")
            .select("*")
            .eq("organization_id", org)
            .order("created_at", desc=True)
            .limit(50)
            .execute()
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed reading escalation overview: %s", type(exc).__name__)
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "Cyber-Model Escalation configuration unavailable."
        ) from None

    policies = [
        EscalationPolicyView(
            id=_as_uuid(r["id"]),
            name=str(r["name"]),
            trigger_kind=r["trigger_kind"],
            threshold_value=float(r.get("threshold_value") or 0.0),
            provider=r["provider"],
            endpoint_url=str(r["endpoint_url"]),
            model_name=str(r["model_name"]),
            key_hint=str(r.get("key_hint") or "••••"),
            circuit_breaker_action=r["circuit_breaker_action"],
            enabled=bool(r.get("enabled", True)),
            created_at=str(r["created_at"]) if r.get("created_at") else None,
        )
        for r in (pol_res.data or [])
    ]
    jobs = [
        EscalationJobView(
            id=_as_uuid(r["id"]),
            policy_id=_as_uuid(r["policy_id"]),
            external_agent_id=str(r["external_agent_id"]),
            trigger_kind=r["trigger_kind"],
            signal_score=float(r.get("signal_score") or 0.0),
            delegation_depth=int(r.get("delegation_depth") or 1),
            redacted_trace=str(r.get("redacted_trace") or ""),
            status=r["status"],
            verdict=r.get("verdict"),
            confidence=float(r["confidence"]) if r.get("confidence") is not None else None,
            action_taken=str(r["action_taken"]) if r.get("action_taken") else None,
            reasoning_summary=str(r["reasoning_summary"]) if r.get("reasoning_summary") else None,
            review_latency_ms=float(r["review_latency_ms"]) if r.get("review_latency_ms") is not None else None,
            created_at=str(r["created_at"]) if r.get("created_at") else None,
            completed_at=str(r["completed_at"]) if r.get("completed_at") else None,
        )
        for r in (job_res.data or [])
    ]
    return EscalationOverviewResponse(policies=policies, jobs=jobs)


def _resolve_managed_target() -> tuple[ModelProvider, str, str, str]:
    from redhand_core.config import get_settings

    settings = get_settings()
    secret = settings.CYBER_MODEL_API_KEY.get_secret_value() if settings.CYBER_MODEL_API_KEY else ""
    if not secret:
        raise SecretVaultError("Managed RedHand Cyber-Model key (CYBER_MODEL_API_KEY) is not configured.")
    provider = settings.CYBER_MODEL_PROVIDER
    model = settings.CYBER_MODEL_NAME
    if provider == "anthropic":
        url = "https://api.anthropic.com/v1/messages"
    elif provider == "openai":
        url = "https://api.openai.com/v1/chat/completions"
    else:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    return (provider, url, model, secret)


async def create_policy(
    supabase: Any, operator: OperatorContext, payload: EscalationPolicyCreate
) -> EscalationPolicyView:
    org = str(operator.organization_id)
    if payload.provider == "managed_redhand":
        from redhand_core.config import get_settings

        settings = get_settings()
        model_name = settings.CYBER_MODEL_NAME
        if settings.CYBER_MODEL_PROVIDER == "anthropic":
            endpoint_url = "https://api.anthropic.com/v1/messages"
        elif settings.CYBER_MODEL_PROVIDER == "openai":
            endpoint_url = "https://api.openai.com/v1/chat/completions"
        else:
            endpoint_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent"
        enc = "managed"
        hint = "MANAGED"
    else:
        endpoint_url = payload.endpoint_url.strip()
        model_name = payload.model_name.strip()
        try:
            outbound.check_url(endpoint_url, allow_insecure=outbound.insecure_webhooks_allowed())
        except outbound.OutboundBlockedError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from None
        raw_key = (payload.api_key or "").strip()
        try:
            enc = encrypt_secret(raw_key, aad=org)
        except SecretVaultError as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from None
        hint = mask_secret(raw_key)

    row_id = str(uuid4())
    now = datetime.now(timezone.utc).isoformat()
    await supabase.table("escalation_policies").insert(
        {
            "id": row_id,
            "organization_id": org,
            "name": payload.name.strip(),
            "trigger_kind": payload.trigger_kind,
            "threshold_value": payload.threshold_value,
            "provider": payload.provider,
            "endpoint_url": endpoint_url,
            "model_name": model_name,
            "encrypted_api_key": enc,
            "key_hint": hint,
            "circuit_breaker_action": payload.circuit_breaker_action,
            "enabled": True,
            "created_by": str(operator.user_id),
            "created_at": now,
            "updated_at": now,
        }
    ).execute()
    return EscalationPolicyView(
        id=UUID(row_id),
        name=payload.name.strip(),
        trigger_kind=payload.trigger_kind,
        threshold_value=payload.threshold_value,
        provider=payload.provider,
        endpoint_url=endpoint_url,
        model_name=model_name,
        key_hint=hint,
        circuit_breaker_action=payload.circuit_breaker_action,
        enabled=True,
        created_at=now,
    )


async def remove_policy(supabase: Any, organization_id: UUID, policy_id: UUID) -> dict[str, bool]:
    res = await (
        supabase.table("escalation_policies")
        .delete()
        .eq("id", str(policy_id))
        .eq("organization_id", str(organization_id))
        .execute()
    )
    if not res.data:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Escalation policy not found.")
    return {"deleted": True}


async def _apply_circuit_breaker(
    supabase: Any, *, org: str, external_agent_id: str, breaker: str
) -> str:
    if breaker == "freeze_agent":
        res = await (
            supabase.table("agents")
            .update({"status": "frozen", "status_reason": "Frozen by Async Cyber-Model Escalation"})
            .eq("organization_id", org)
            .eq("external_agent_id", external_agent_id)
            .execute()
        )
        return "agent_frozen" if res.data else "freeze_no_matching_agent"
    if breaker == "safe_mode":
        await supabase.table("organizations").update({"safe_mode": True}).eq("id", org).execute()
        return "org_safe_mode_enabled"
    return "hitl_escalation_flagged"


async def evaluate_trace(
    supabase: Any, organization_id: UUID, payload: EscalationEvaluateRequest
) -> EscalationJobView:
    """Selects matching policy, scrubs trace, dispatches to Managed or BYOK endpoint, and applies breaker."""
    org = str(organization_id)
    pol_res = await (
        supabase.table("escalation_policies")
        .select("*")
        .eq("organization_id", org)
        .eq("trigger_kind", payload.trigger_kind)
        .execute()
    )
    candidates = [
        p for p in (pol_res.data or []) if bool(p.get("enabled", True))
        and (
            (payload.trigger_kind == "delegation_depth" and payload.delegation_depth >= float(p.get("threshold_value") or 0))
            or (payload.trigger_kind != "delegation_depth" and payload.signal_score >= float(p.get("threshold_value") or 0))
        )
    ]
    if not candidates:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "No enabled escalation policy matched this trigger and threshold.",
        )

    policy = candidates[0]
    redacted = redact_trace_for_model(payload.trace_excerpt)
    job_id = str(uuid4())
    now = datetime.now(timezone.utc).isoformat()
    await supabase.table("escalation_jobs").insert(
        {
            "id": job_id,
            "organization_id": org,
            "policy_id": str(policy["id"]),
            "external_agent_id": payload.external_agent_id,
            "trigger_kind": payload.trigger_kind,
            "signal_score": payload.signal_score,
            "delegation_depth": payload.delegation_depth,
            "redacted_trace": redacted,
            "status": "processing",
            "created_at": now,
            "updated_at": now,
        }
    ).execute()

    t0 = time.monotonic()
    verdict = "inconclusive"
    confidence = 0.0
    reasoning = ""
    action_taken = "none"
    final_status = "completed"

    try:
        configured_provider: ModelProvider = policy["provider"]
        if configured_provider == "managed_redhand":
            upstream_provider, endpoint_url, model_name, key = _resolve_managed_target()
        else:
            upstream_provider = configured_provider
            endpoint_url = str(policy["endpoint_url"])
            model_name = str(policy["model_name"])
            key = decrypt_secret(str(policy["encrypted_api_key"]), aad=org)
        resp = await outbound.post_json(
            endpoint_url,
            _provider_payload(upstream_provider, model_name, redacted, payload.trigger_kind),
            allow_insecure=outbound.insecure_webhooks_allowed(),
            headers=_provider_headers(upstream_provider, key),
            timeout=5.0,
        )
        resp.raise_for_status()
        verdict, confidence, reasoning = _parse_verdict(resp.content)
        if verdict == "malicious" and confidence >= 0.7:
            action_taken = await _apply_circuit_breaker(
                supabase,
                org=org,
                external_agent_id=payload.external_agent_id,
                breaker=str(policy["circuit_breaker_action"]),
            )
    except (SecretVaultError, outbound.OutboundError) as exc:
        final_status = "failed"
        reasoning = str(exc)
        if isinstance(exc, outbound.OutboundBlockedError):
            outbound.record_blocked("cyber_escalation")

    elapsed_ms = round((time.monotonic() - t0) * 1000.0, 2)
    completed_at = datetime.now(timezone.utc).isoformat()
    await (
        supabase.table("escalation_jobs")
        .update(
            {
                "status": final_status,
                "verdict": verdict,
                "confidence": confidence,
                "action_taken": action_taken,
                "reasoning_summary": reasoning,
                "review_latency_ms": elapsed_ms,
                "completed_at": completed_at,
            }
        )
        .eq("id", job_id)
        .execute()
    )
    return EscalationJobView(
        id=UUID(job_id),
        policy_id=_as_uuid(policy["id"]),
        external_agent_id=payload.external_agent_id,
        trigger_kind=payload.trigger_kind,
        signal_score=payload.signal_score,
        delegation_depth=payload.delegation_depth,
        redacted_trace=redacted,
        status=final_status,  # type: ignore[arg-type]
        verdict=verdict,  # type: ignore[arg-type]
        confidence=confidence,
        action_taken=action_taken,
        reasoning_summary=reasoning,
        review_latency_ms=elapsed_ms,
        created_at=now,
        completed_at=completed_at,
    )


async def maybe_escalate_blocked_events(
    supabase: Any,
    organization_id: UUID,
    agent_summaries: list[tuple[str, str]],
) -> None:
    """Background hook from `/internal/v1/events`: dispatches high-risk blocks when an escalation policy exists."""
    if not agent_summaries:
        return
    try:
        res = await (
            supabase.table("escalation_policies")
            .select("id")
            .eq("organization_id", str(organization_id))
            .eq("enabled", True)
            .limit(1)
            .execute()
        )
        if not res.data:
            return
        for external_agent_id, summary in agent_summaries[:5]:
            try:
                await evaluate_trace(
                    supabase,
                    organization_id,
                    EscalationEvaluateRequest(
                        external_agent_id=external_agent_id,
                        trigger_kind="onnx_borderline",
                        signal_score=0.75,
                        delegation_depth=1,
                        trace_excerpt=summary,
                    ),
                )
            except HTTPException:
                continue
    except Exception as exc:  # noqa: BLE001 - background hook never raises
        logger.warning("Background escalation hook error: %s", type(exc).__name__)
