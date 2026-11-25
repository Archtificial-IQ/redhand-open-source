"""Async Deep Cyber-Model Escalation & Sub-Agent Circuit-Breaker router."""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, status

from redhand_core.auth.operator import AdminDep, SecurityOperatorDep
from redhand_core.escalation import service as escalation_service
from redhand_core.escalation.models import (
    EscalationEvaluateRequest,
    EscalationJobView,
    EscalationOverviewResponse,
    EscalationPolicyCreate,
    EscalationPolicyView,
)
from redhand_core.routers.telemetry import get_supabase_service_client

router = APIRouter(prefix="/v1/escalation", tags=["Cyber-Model Escalation"])
SupabaseDep = Annotated[Any, Depends(get_supabase_service_client)]


@router.get("/overview", response_model=EscalationOverviewResponse)
async def get_escalation_overview(
    operator: SecurityOperatorDep, supabase: SupabaseDep
) -> EscalationOverviewResponse:
    return await escalation_service.get_overview(supabase, operator.organization_id)


@router.post("/policies", response_model=EscalationPolicyView, status_code=status.HTTP_201_CREATED)
async def create_escalation_policy(
    payload: EscalationPolicyCreate, operator: AdminDep, supabase: SupabaseDep
) -> EscalationPolicyView:
    return await escalation_service.create_policy(supabase, operator, payload)


@router.delete("/policies/{policy_id}")
async def remove_escalation_policy(
    policy_id: UUID, operator: AdminDep, supabase: SupabaseDep
) -> dict[str, bool]:
    return await escalation_service.remove_policy(supabase, operator.organization_id, policy_id)


@router.post("/evaluate", response_model=EscalationJobView)
async def evaluate_escalation_trace(
    payload: EscalationEvaluateRequest, operator: SecurityOperatorDep, supabase: SupabaseDep
) -> EscalationJobView:
    return await escalation_service.evaluate_trace(supabase, operator.organization_id, payload)
