"""Pydantic schemas for Ephemeral IAM Broker connections, policies, and mint audit events."""

from __future__ import annotations

import re
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

IamProvider = Literal["aws_sts", "gcp_sts"]

_AWS_ROLE_RE = re.compile(r"^arn:aws[a-zA-Z-]*:iam::\d{12}:role/[\w+=,.@/-]+$")
_GCP_SA_RE = re.compile(r"^[a-zA-Z0-9._-]+@[a-z0-9.-]+\.iam\.gserviceaccount\.com$")


class CloudConnectionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: IamProvider
    display_name: str = Field(..., min_length=2, max_length=120)
    principal_identifier: str = Field(..., min_length=8, max_length=512)
    region_or_project: str = Field(default="global", min_length=2, max_length=128)

    @model_validator(mode="after")
    def _validate_principal(self) -> CloudConnectionCreate:
        principal = self.principal_identifier.strip()
        self.principal_identifier = principal
        self.display_name = self.display_name.strip()
        self.region_or_project = self.region_or_project.strip()
        if self.provider == "aws_sts" and not _AWS_ROLE_RE.match(principal):
            raise ValueError("AWS connection must be a valid IAM Role ARN (arn:aws:iam::<12-digits>:role/<name>).")
        if self.provider == "gcp_sts" and not _GCP_SA_RE.match(principal):
            raise ValueError("GCP connection must be a Service Account email (*.iam.gserviceaccount.com).")
        return self


class CloudConnectionView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    provider: IamProvider
    display_name: str
    principal_identifier: str
    region_or_project: str
    status: str
    created_at: str | None = None


class IamPolicyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    external_agent_id: str = Field(..., min_length=1, max_length=128)
    tool_name: str = Field(..., min_length=1, max_length=256)
    provider: IamProvider
    target_principal: str = Field(..., min_length=8, max_length=512)
    target_resource: str = Field(..., min_length=8, max_length=512)
    allowed_actions: list[str] = Field(..., min_length=1, max_length=20)
    ttl_seconds: int = Field(default=60, ge=15, le=43200)

    @field_validator("target_resource")
    @classmethod
    def _no_wildcard_resource(cls, v: str) -> str:
        cleaned = v.strip()
        if cleaned == "*" or "*" == cleaned.strip("/"):
            raise ValueError("Wildcard '*' resource is forbidden.")
        return cleaned

    @model_validator(mode="after")
    def _validate_provider_bounds(self) -> IamPolicyCreate:
        self.external_agent_id = self.external_agent_id.strip()
        self.tool_name = self.tool_name.strip()
        self.target_principal = self.target_principal.strip()
        self.allowed_actions = [a.strip() for a in self.allowed_actions if a.strip()]
        if not self.allowed_actions:
            raise ValueError("At least one granular action or permission is required.")
        if self.provider == "aws_sts":
            if not _AWS_ROLE_RE.match(self.target_principal):
                raise ValueError("AWS target_principal must be a valid IAM Role ARN.")
            if not self.target_resource.startswith("arn:aws"):
                raise ValueError("AWS target_resource must start with 'arn:aws'.")
        else:
            if not self.target_resource.startswith("//") or ".googleapis.com/" not in self.target_resource:
                raise ValueError("GCP target_resource must start with '//' and include '.googleapis.com/'.")
            if "*" in self.target_resource:
                raise ValueError("Wildcards ('*') are forbidden in GCP target_resource URIs.")
            if self.ttl_seconds > 60:
                raise ValueError("GCP downscoped tokens cannot exceed 60 seconds TTL.")
        return self


class IamPolicyView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    external_agent_id: str
    tool_name: str
    provider: IamProvider
    target_principal: str
    target_resource: str
    allowed_actions: list[str]
    ttl_seconds: int
    enabled: bool
    created_at: str | None = None


class IamMintEventView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    external_agent_id: str
    tool_name: str
    provider: IamProvider
    token_jti: str
    trace_id: str
    span_id: str
    outcome: Literal["minted", "denied"]
    detail: str | None = None
    expires_at: str | None = None
    mint_latency_ms: float = 0.0
    created_at: str | None = None


class IamOverviewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    connections: list[CloudConnectionView]
    policies: list[IamPolicyView]
    recent_mints: list[IamMintEventView]
    microsoft_entra_status: Literal["coming_soon"] = "coming_soon"
