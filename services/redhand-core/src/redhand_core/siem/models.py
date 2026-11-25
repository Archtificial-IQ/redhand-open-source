"""Pydantic contracts for OCSF SIEM connectors, durable outbox, and STIX/TAXII 2.1 feeds."""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

ConnectorType = Literal["splunk_hec", "sentinel_logs", "google_secops"]
IndicatorType = Literal["domain", "ipv4", "sha256"]


class SiemConnectorCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    connector_type: ConnectorType
    name: str = Field(..., min_length=2, max_length=120)
    endpoint_url: str = Field(..., min_length=12, max_length=512)
    auth_token: str = Field(..., min_length=8, max_length=2048)


class SiemConnectorView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    connector_type: ConnectorType
    name: str
    endpoint_url: str
    token_hint: str
    enabled: bool
    last_shipped_at: str | None = None
    last_error: str | None = None
    created_at: str | None = None


class ThreatFeedCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=2, max_length=120)
    collection_url: str = Field(..., min_length=12, max_length=512)
    auth_token: str | None = Field(default=None, max_length=2048)
    poll_interval_minutes: int = Field(default=5, ge=1, le=1440)


class ThreatFeedView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    name: str
    collection_url: str
    token_hint: str | None = None
    poll_interval_minutes: int
    enabled: bool
    last_synced_at: str | None = None
    last_indicator_count: int = 0
    last_error: str | None = None
    created_at: str | None = None


class ThreatIndicatorView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    feed_id: UUID
    indicator_type: IndicatorType
    indicator_value: str
    confidence: int
    stix_id: str
    created_at: str | None = None


class OutboxSummaryView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pending: int
    delivered: int
    dead_letter: int


class SiemOverviewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    connectors: list[SiemConnectorView]
    feeds: list[ThreatFeedView]
    indicators: list[ThreatIndicatorView]
    outbox: OutboxSummaryView


class SiemTestResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    delivered: bool
    status: Literal["delivered", "pending", "dead_letter"]
    detail: str


class TaxiiSyncResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    feed_id: UUID
    imported_count: int
    status: Literal["synced", "failed"]
    detail: str
