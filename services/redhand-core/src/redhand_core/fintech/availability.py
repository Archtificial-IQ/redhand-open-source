"""
Whether the Fintech Shield is included for an organization (ADR 0033, decision 2).

It is included for every organization today. This is the single place a future billing tier would decide, so nothing else (core, the gateway
context, the gateway) needs to change when tiers exist.
"""

from __future__ import annotations

from uuid import UUID


def fintech_shield_available(organization_id: UUID) -> bool:
    del (
        organization_id
    )  # every organization has it today; kept so callers already pass what a tier check will need
    return True
