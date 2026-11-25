"""
The Fintech Shield settings and payment-tool bindings: tenant-scoped reads and audited changes (in SQL). See docs/plans/phase6-fintech-shield.md.

Who may do what is decided by the router's role dependencies; the organization comes from the verified operator, never from the request.
Turning enforcement on refuses calls and turning the shield off removes a safeguard, so both need an explicit confirmation; so does changing a
binding while the organization is enforcing, because it changes what is refused.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import HTTPException, status

from redhand_core.auth.operator import OperatorContext, Role
from redhand_core.fintech.availability import fintech_shield_available
from redhand_core.fintech.models import (
    FintechBinding,
    FintechBindingRemoveResponse,
    FintechBindingRequest,
    FintechBindingResponse,
    FintechCapabilities,
    FintechSettingsRequest,
    FintechSettingsResponse,
)
from redhand_core.passports.service import _require_confirmation, _rpc

NOT_AVAILABLE = "The Fintech Shield is not included for this organization."


async def _settings_data(supabase: Any, operator: OperatorContext) -> dict[str, Any]:
    data: dict[str, Any] = await _rpc(
        supabase,
        "fintech_settings",
        {"p_org": str(operator.organization_id)},
        not_found_detail="Organization not found.",
        conflict_detail="The Fintech Shield settings could not be read.",
    )
    return data


def _require_available(operator: OperatorContext) -> None:
    if not fintech_shield_available(operator.organization_id):
        raise HTTPException(status.HTTP_403_FORBIDDEN, NOT_AVAILABLE)


async def get_settings(supabase: Any, operator: OperatorContext) -> FintechSettingsResponse:
    data = await _settings_data(supabase, operator)
    return FintechSettingsResponse(
        available=fintech_shield_available(operator.organization_id),
        fintech_shield_mode=data["fintech_shield_mode"],
        fintech_shield_mode_changed_at=data.get("fintech_shield_mode_changed_at"),
        holidays=list(data.get("fintech_holidays") or []),
        bindings=[FintechBinding.model_validate(b) for b in data.get("bindings") or []],
        capabilities=FintechCapabilities(
            can_change=operator.role is not None and operator.role >= Role.ADMIN
        ),
    )


async def set_settings(
    supabase: Any, operator: OperatorContext, request: FintechSettingsRequest
) -> FintechSettingsResponse:
    """Compare-and-set against the mode the caller saw, and replace the holiday list."""
    _require_available(operator)
    if request.fintech_shield_mode == "enforce" and request.expected_mode != "enforce":
        _require_confirmation(
            request.confirm,
            "Turning Fintech Shield enforcement on (bound payment calls that break a rule are refused)",
        )
    if request.fintech_shield_mode == "off" and request.expected_mode != "off":
        _require_confirmation(request.confirm, "Turning the Fintech Shield off")
    data = await _rpc(
        supabase,
        "control_fintech_settings",
        {
            "p_org": str(operator.organization_id),
            "p_actor": str(operator.user_id),
            "p_mode": request.fintech_shield_mode,
            "p_expected_mode": request.expected_mode,
            "p_holidays": [d.isoformat() for d in request.holidays],
            "p_reason": request.reason,
        },
        not_found_detail="Organization not found.",
        conflict_detail="The Fintech Shield settings could not be changed.",
    )
    if data.get("conflict"):
        raise HTTPException(
            status.HTTP_409_CONFLICT, "The mode was changed by someone else. Reload and try again."
        )
    if data.get("no_bindings"):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Bind at least one payment tool before turning enforcement on.",
        )
    return await get_settings(supabase, operator)


async def _require_confirmation_if_enforcing(
    supabase: Any, operator: OperatorContext, confirm: bool, action: str
) -> None:
    data = await _settings_data(supabase, operator)
    if data.get("fintech_shield_mode") == "enforce":
        _require_confirmation(confirm, f"{action} while the Fintech Shield is enforcing")


async def upsert_binding(
    supabase: Any,
    operator: OperatorContext,
    server_id: UUID,
    tool: str,
    request: FintechBindingRequest,
) -> FintechBindingResponse:
    _require_available(operator)
    await _require_confirmation_if_enforcing(
        supabase, operator, request.confirm, "Changing a payment-tool binding"
    )
    data = await _rpc(
        supabase,
        "control_fintech_binding_upsert",
        {
            "p_org": str(operator.organization_id),
            "p_actor": str(operator.user_id),
            "p_server": str(server_id),
            "p_tool": tool,
            "p_amount_path": request.amount_path,
            "p_currency_path": request.currency_path,
            "p_fixed_currency": request.fixed_currency,
            "p_beneficiary_path": request.beneficiary_path,
            "p_reason": request.reason,
        },
        not_found_detail="MCP server not found.",
        conflict_detail="The binding could not be saved.",
    )
    if data.get("limit"):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "This server already has 50 bound payment tools. Remove one first.",
        )
    return FintechBindingResponse(
        id=data["id"], tool=tool, created=bool(data["created"]), changed=bool(data["changed"])
    )


async def remove_binding(
    supabase: Any,
    operator: OperatorContext,
    server_id: UUID,
    binding_id: UUID,
    confirm: bool,
    reason: str | None,
) -> FintechBindingRemoveResponse:
    _require_available(operator)
    await _require_confirmation_if_enforcing(
        supabase, operator, confirm, "Removing a payment-tool binding"
    )
    data = await _rpc(
        supabase,
        "control_fintech_binding_remove",
        {
            "p_org": str(operator.organization_id),
            "p_actor": str(operator.user_id),
            "p_server": str(server_id),
            "p_binding": str(binding_id),
            "p_reason": reason,
        },
        not_found_detail="Binding not found.",
        conflict_detail="The binding could not be removed.",
    )
    if data.get("last_binding_in_enforce"):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "This is the last bound payment tool and the Fintech Shield is enforcing. Switch it to Watch or Off first.",
        )
    return FintechBindingRemoveResponse(removed=bool(data["removed"]))
