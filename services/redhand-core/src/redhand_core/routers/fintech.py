"""
Fintech Shield settings and payment-tool bindings (Phase 6 S1). See docs/plans/phase6-fintech-shield.md and ADR 0033.

GET    /v1/fintech/settings                                         mode, holidays and every binding (security operator)
PUT    /v1/fintech/settings                                         mode (compare and set) and holidays (admin; enforce and off need a confirmation)
PUT    /v1/mcp-servers/{server_id}/fintech-bindings/{tool}          bind a payment tool or change its paths (admin, audited)
DELETE /v1/mcp-servers/{server_id}/fintech-bindings/{binding_id}    unbind it (admin, audited; the last one cannot go while enforcing)

The gateway reads the settings through /internal/v1/gateway-context. The UI is never a security boundary: every change is authorized here.
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Path, Query

from redhand_core.auth.operator import AdminDep, SecurityOperatorDep
from redhand_core.fintech import service
from redhand_core.fintech.models import (
    TOOL_NAME_PATTERN,
    FintechBindingRemoveResponse,
    FintechBindingRequest,
    FintechBindingResponse,
    FintechSettingsRequest,
    FintechSettingsResponse,
)
from redhand_core.passports.models import MAX_REASON_LENGTH
from redhand_core.routers.telemetry import get_supabase_service_client

router = APIRouter(tags=["Fintech Shield"])
SupabaseDep = Annotated[Any, Depends(get_supabase_service_client)]
ToolName = Annotated[
    str, Path(pattern=TOOL_NAME_PATTERN, description="The tool's name as the MCP server lists it.")
]


@router.get("/v1/fintech/settings", response_model=FintechSettingsResponse)
async def get_fintech_settings(
    operator: SecurityOperatorDep, supabase: SupabaseDep
) -> FintechSettingsResponse:
    return await service.get_settings(supabase, operator)


@router.put("/v1/fintech/settings", response_model=FintechSettingsResponse)
async def put_fintech_settings(
    payload: FintechSettingsRequest, operator: AdminDep, supabase: SupabaseDep
) -> FintechSettingsResponse:
    """observe records rule breaks on bound payment tools and refuses nothing. enforce also refuses them (needs a bound tool and confirm: true).
    off checks nothing (needs confirm: true). The body carries the mode the caller saw, and the full holiday list."""
    return await service.set_settings(supabase, operator, payload)


@router.put(
    "/v1/mcp-servers/{server_id}/fintech-bindings/{tool}", response_model=FintechBindingResponse
)
async def put_fintech_binding(
    server_id: UUID,
    tool: ToolName,
    payload: FintechBindingRequest,
    operator: AdminDep,
    supabase: SupabaseDep,
) -> FintechBindingResponse:
    """Marks the tool as a payment tool and says where its amount, currency and payee are. Binding the same paths again changes nothing."""
    return await service.upsert_binding(supabase, operator, server_id, tool, payload)


@router.delete(
    "/v1/mcp-servers/{server_id}/fintech-bindings/{binding_id}",
    response_model=FintechBindingRemoveResponse,
)
async def remove_fintech_binding(
    server_id: UUID,
    binding_id: UUID,
    operator: AdminDep,
    supabase: SupabaseDep,
    confirm: bool = Query(
        default=False, description="Required while the organization is enforcing."
    ),
    reason: str | None = Query(default=None, max_length=MAX_REASON_LENGTH),
) -> FintechBindingRemoveResponse:
    return await service.remove_binding(supabase, operator, server_id, binding_id, confirm, reason)
