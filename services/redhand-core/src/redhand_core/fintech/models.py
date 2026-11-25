"""
Models for the Fintech Shield settings and payment-tool bindings (Phase 6 S1, docs/plans/phase6-fintech-shield.md, ADR 0033).

A binding names WHERE a payment tool's amount, currency and payee sit in its arguments (dotted paths such as `payment.amount` or
`payments[*].amount`). It never holds a value. The path grammar is the one the gateway's rule engine (redhand-certin-0058-preset, its
`ArgPath`) accepts: no filters, no recursion, nothing an agent's arguments could make expensive. S2 adds a contract test that the two agree.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator

from redhand_core.passports.models import MAX_REASON_LENGTH

FintechMode = Literal["off", "observe", "enforce"]
ARG_PATH_PATTERN = (
    r"^[A-Za-z_][A-Za-z0-9_-]*(\[(\*|[0-9]+)\])?(\.[A-Za-z_][A-Za-z0-9_-]*(\[(\*|[0-9]+)\])?)*$"
)
TOOL_NAME_PATTERN = r"^[A-Za-z0-9_.-]{1,128}$"
CURRENCY_PATTERN = r"^[A-Z]{3}$"
MAX_PATH_LENGTH = 256
MAX_BINDINGS_PER_SERVER = 50
MAX_HOLIDAYS = 60
# Holidays outside this range are almost certainly typing mistakes (a year of 0226 or 2926), so they are refused rather than stored.
EARLIEST_HOLIDAY = date(2020, 1, 1)
LATEST_HOLIDAY = date(2100, 12, 31)

ArgPath = Field(min_length=1, max_length=MAX_PATH_LENGTH, pattern=ARG_PATH_PATTERN)


class FintechBinding(BaseModel):
    id: UUID
    server_id: UUID
    server_slug: str
    tool: str
    amount_path: str
    currency_path: str | None = None
    fixed_currency: str | None = None
    beneficiary_path: str | None = None
    updated_at: datetime


class FintechCapabilities(BaseModel):
    """What the signed-in operator may do, so the UI hides buttons the server would refuse. The server enforces it anyway."""

    can_change: bool


class FintechSettingsResponse(BaseModel):
    available: bool = Field(
        description="Whether the Fintech Shield is included for this organization (true for every organization today)."
    )
    fintech_shield_mode: FintechMode
    fintech_shield_mode_changed_at: datetime | None = None
    holidays: list[date]
    bindings: list[FintechBinding]
    max_bindings_per_server: int = MAX_BINDINGS_PER_SERVER
    max_holidays: int = MAX_HOLIDAYS
    capabilities: FintechCapabilities


class FintechSettingsRequest(BaseModel):
    """The whole settings state (a PUT replaces it): the mode, compared against the mode the caller saw, and the holiday list."""

    model_config = ConfigDict(extra="forbid")

    fintech_shield_mode: FintechMode
    expected_mode: FintechMode = Field(
        description="The mode the caller saw; a different current mode is a conflict."
    )
    holidays: list[date] = Field(
        max_length=MAX_HOLIDAYS, description="Public holidays for the off-hours rule (dates only)."
    )
    reason: str | None = Field(default=None, max_length=MAX_REASON_LENGTH)
    confirm: StrictBool = Field(
        default=False,
        description="Required to turn enforcement on (it refuses calls) or to turn the shield off.",
    )

    @field_validator("holidays")
    @classmethod
    def _holidays_are_distinct_and_plausible(cls, value: list[date]) -> list[date]:
        if len(set(value)) != len(value):
            raise ValueError("each holiday may appear only once")
        if any(d < EARLIEST_HOLIDAY or d > LATEST_HOLIDAY for d in value):
            raise ValueError(
                f"holidays must fall between {EARLIEST_HOLIDAY.isoformat()} and {LATEST_HOLIDAY.isoformat()}"
            )
        return sorted(value)


class FintechBindingRequest(BaseModel):
    """Which argument holds the amount, the currency (or one fixed currency for the tool) and, optionally, the payee."""

    model_config = ConfigDict(extra="forbid")

    amount_path: str = ArgPath
    currency_path: str | None = Field(
        default=None, min_length=1, max_length=MAX_PATH_LENGTH, pattern=ARG_PATH_PATTERN
    )
    fixed_currency: str | None = Field(default=None, pattern=CURRENCY_PATTERN)
    beneficiary_path: str | None = Field(
        default=None, min_length=1, max_length=MAX_PATH_LENGTH, pattern=ARG_PATH_PATTERN
    )
    reason: str | None = Field(default=None, max_length=MAX_REASON_LENGTH)
    confirm: StrictBool = Field(
        default=False,
        description="Required while the organization is enforcing: the change alters what is refused.",
    )

    @model_validator(mode="after")
    def _exactly_one_currency_source(self) -> Self:
        if (self.currency_path is None) == (self.fixed_currency is None):
            raise ValueError("give exactly one of currency_path or fixed_currency")
        return self


class FintechBindingResponse(BaseModel):
    id: UUID
    tool: str
    created: bool = Field(description="True when the tool was not bound before.")
    changed: bool = Field(description="False when the same paths were already stored.")


class FintechBindingRemoveResponse(BaseModel):
    removed: bool
