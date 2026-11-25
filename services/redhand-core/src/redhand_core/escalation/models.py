"""Pydantic models for Async Deep Cyber-Model Escalation policies and triage jobs."""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

TriggerKind = Literal["onnx_borderline", "delegation_depth", "obfuscation_drift"]
ModelProvider = Literal["managed_redhand", "anthropic", "openai", "gemini_vertex", "custom_vpc"]
BreakerAction = Literal["freeze_agent", "safe_mode", "hitl_review"]


class EscalationPolicyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=2, max_length=120)
    trigger_kind: TriggerKind
    threshold_value: float = Field(..., ge=0.0, le=100.0)
    provider: ModelProvider
    endpoint_url: str = Field(default="https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent", min_length=12, max_length=512)
    model_name: str = Field(default="gemini-2.5-flash", min_length=2, max_length=128)
    api_key: str | None = Field(default=None, max_length=2048)
    circuit_breaker_action: BreakerAction

    @model_validator(mode="after")
    def _validate_credentials(self) -> EscalationPolicyCreate:
        if self.provider != "managed_redhand":
            if not self.api_key or len(self.api_key.strip()) < 8:
                raise ValueError("BYOK escalation policies require an API key (at least 8 characters).")
        return self


class EscalationPolicyView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    name: str
    trigger_kind: TriggerKind
    threshold_value: float
    provider: ModelProvider
    endpoint_url: str
    model_name: str
    key_hint: str
    circuit_breaker_action: BreakerAction
    enabled: bool
    created_at: str | None = None


class EscalationEvaluateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    external_agent_id: str = Field(..., min_length=1, max_length=128)
    trigger_kind: TriggerKind
    signal_score: float = Field(..., ge=0.0, le=100.0)
    delegation_depth: int = Field(default=1, ge=1, le=32)
    trace_excerpt: str = Field(..., min_length=4, max_length=8000)


class EscalationJobView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    policy_id: UUID
    external_agent_id: str
    trigger_kind: TriggerKind
    signal_score: float
    delegation_depth: int
    redacted_trace: str
    status: Literal["pending", "processing", "completed", "failed"]
    verdict: Literal["malicious", "benign", "inconclusive"] | None = None
    confidence: float | None = None
    action_taken: str | None = None
    reasoning_summary: str | None = None
    review_latency_ms: float | None = None
    created_at: str | None = None
    completed_at: str | None = None


class EscalationOverviewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policies: list[EscalationPolicyView]
    jobs: list[EscalationJobView]
