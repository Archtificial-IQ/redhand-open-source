"""Enterprise SIEM (OCSF v1.1.0) & Threat Intel (STIX/TAXII 2.1) router."""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, status

from redhand_core.auth.operator import AdminDep, SecurityOperatorDep
from redhand_core.routers.telemetry import get_supabase_service_client
from redhand_core.siem import service as siem_service
from redhand_core.siem.models import (
    SiemConnectorCreate,
    SiemConnectorView,
    SiemOverviewResponse,
    SiemTestResult,
    TaxiiSyncResult,
    ThreatFeedCreate,
    ThreatFeedView,
)

router = APIRouter(prefix="/v1/siem", tags=["SIEM & Threat Intel"])
SupabaseDep = Annotated[Any, Depends(get_supabase_service_client)]


@router.get("/overview", response_model=SiemOverviewResponse)
async def get_siem_overview(operator: SecurityOperatorDep, supabase: SupabaseDep) -> SiemOverviewResponse:
    return await siem_service.get_overview(supabase, operator.organization_id)


@router.post("/connectors", response_model=SiemConnectorView, status_code=status.HTTP_201_CREATED)
async def create_siem_connector(
    payload: SiemConnectorCreate, operator: AdminDep, supabase: SupabaseDep
) -> SiemConnectorView:
    return await siem_service.create_connector(supabase, operator, payload)


@router.delete("/connectors/{connector_id}")
async def remove_siem_connector(
    connector_id: UUID, operator: AdminDep, supabase: SupabaseDep
) -> dict[str, bool]:
    return await siem_service.remove_connector(supabase, operator.organization_id, connector_id)


@router.post("/connectors/{connector_id}/test", response_model=SiemTestResult)
async def test_siem_connector(
    connector_id: UUID, operator: AdminDep, supabase: SupabaseDep
) -> SiemTestResult:
    return await siem_service.test_connector(supabase, operator.organization_id, connector_id)


@router.post("/feeds", response_model=ThreatFeedView, status_code=status.HTTP_201_CREATED)
async def create_threat_feed(
    payload: ThreatFeedCreate, operator: AdminDep, supabase: SupabaseDep
) -> ThreatFeedView:
    return await siem_service.create_feed(supabase, operator, payload)


@router.post("/feeds/{feed_id}/sync", response_model=TaxiiSyncResult)
async def sync_threat_feed(
    feed_id: UUID, operator: SecurityOperatorDep, supabase: SupabaseDep
) -> TaxiiSyncResult:
    return await siem_service.sync_feed(supabase, operator.organization_id, feed_id)


@router.delete("/feeds/{feed_id}")
async def remove_threat_feed(
    feed_id: UUID, operator: AdminDep, supabase: SupabaseDep
) -> dict[str, bool]:
    return await siem_service.remove_feed(supabase, operator.organization_id, feed_id)
