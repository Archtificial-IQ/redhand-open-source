"""
Fintech Shield, core side (Phase 6 S1, docs/plans/phase6-fintech-shield.md, ADR 0033): who may read and change the settings and the
payment-tool bindings, what needs a confirmation, what is validated before anything is stored, that every change is audited without values,
that nothing crosses organizations, and what the gateway's context carries (and how it fails).
"""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

from pydantic import SecretStr
import pytest

from redhand_core.fintech.availability import fintech_shield_available
from redhand_core.services.local_store import DEFAULT_ORG_ID

from core_helpers import operator_headers
from test_telegram import OTHER_ORG, Env as TelegramEnv

SERVICE_TOKEN = "fintech-core-test-internal-service-token-0123456789"
OTHER_OWNER = "00000000-0000-0000-0000-0000000000f3"
GATEWAY_HEADERS = {"Authorization": f"Bearer {SERVICE_TOKEN}"}
SETTINGS = "/v1/fintech/settings"
PAY = {"amount_path": "payment.amount", "currency_path": "payment.currency", "beneficiary_path": "payee.vpa"}


class Env(TelegramEnv):
    def __init__(self) -> None:
        super().__init__(INTERNAL_SERVICE_TOKEN=SecretStr(SERVICE_TOKEN), ALLOW_INSECURE_MCP_URLS=True)
        self.agent = self.register("Payments bot")["id"]
        self.server_id = self.server("xero")

    def server(self, slug: str) -> str:
        resp = self.client.post("/v1/mcp-servers", json={"slug": slug, "name": "Demo", "url": "http://demo.test/mcp"}, headers=self.h("admin"))
        assert resp.status_code == 201, resp.text
        return str(resp.json()["id"])

    def get(self, user: str = "operator", headers: dict[str, str] | None = None) -> Any:
        return self.client.get(SETTINGS, headers=headers or self.h(user))

    def put(self, mode: str, expected: str, holidays: list[str] | None = None, user: str = "admin", **extra: Any) -> Any:
        body = {"fintech_shield_mode": mode, "expected_mode": expected, "holidays": holidays or [], **extra}
        return self.client.put(SETTINGS, json=body, headers=extra.pop("headers", None) or self.h(user))

    def bind(self, tool: str = "transfer_funds", server_id: str | None = None, user: str = "admin", headers: dict[str, str] | None = None,
             **body: Any) -> Any:
        url = f"/v1/mcp-servers/{server_id or self.server_id}/fintech-bindings/{tool}"
        return self.client.put(url, json=body or dict(PAY), headers=headers or self.h(user))

    def unbind(self, binding_id: str, server_id: str | None = None, user: str = "admin", headers: dict[str, str] | None = None,
               **params: Any) -> Any:
        url = f"/v1/mcp-servers/{server_id or self.server_id}/fintech-bindings/{binding_id}"
        return self.client.delete(url, params=params, headers=headers or self.h(user))

    def other_headers(self) -> dict[str, str]:
        return operator_headers(settings=self.settings, user_id=UUID(OTHER_OWNER))

    def other_server(self) -> str:
        server_id = str(uuid4())
        self.store.tables["mcp_servers"].append(
            {"id": server_id, "organization_id": OTHER_ORG, "slug": "xero", "name": "Theirs", "url": "http://other.test/mcp", "is_active": True}
        )
        return server_id

    def audit_actions(self, name: str) -> list[dict[str, Any]]:
        return [r for r in self.store.tables.get("control_audit_log", []) if r["action"] == name]

    def context(self, server: str = "xero") -> Any:
        params = {"agent_id": self.agent, "organization_id": DEFAULT_ORG_ID, "server": server, "instance_id": "gateway-test-0001"}
        return self.client.get("/internal/v1/gateway-context", params=params, headers=GATEWAY_HEADERS)

    def org(self) -> dict[str, Any]:
        return next(o for o in self.store.tables["organizations"] if o["id"] == DEFAULT_ORG_ID)


@pytest.fixture
def env() -> Env:
    return Env()


# --- defaults and roles ------------------------------------------------------------------------------------------------------------------

def test_every_organization_starts_in_observe_with_nothing_bound(env: Env) -> None:
    body = env.get().json()
    assert body["available"] is True and body["fintech_shield_mode"] == "observe"
    assert body["holidays"] == [] and body["bindings"] == [] and body["max_bindings_per_server"] == 50
    assert fintech_shield_available(uuid4()) is True


def test_a_security_operator_reads_but_only_an_admin_changes(env: Env) -> None:
    assert env.get("operator").json()["capabilities"]["can_change"] is False
    assert env.get("admin").json()["capabilities"]["can_change"] is True
    assert env.get("viewer").status_code == 403
    assert env.put("observe", "observe", ["2026-08-31"], user="operator").status_code == 403
    assert env.bind(user="operator").status_code == 403
    assert env.get().json()["holidays"] == [] and env.get().json()["bindings"] == []


# --- the mode ----------------------------------------------------------------------------------------------------------------------------

def test_enforce_needs_a_bound_tool_and_a_confirmation(env: Env) -> None:
    assert env.put("enforce", "observe", confirm=True).status_code == 409  # nothing bound: enforce would judge nothing
    assert env.bind().status_code == 200
    resp = env.put("enforce", "observe")
    assert resp.status_code == 400 and "confirmation" in resp.json()["detail"]
    resp = env.put("enforce", "observe", confirm=True)
    assert resp.status_code == 200 and resp.json()["fintech_shield_mode"] == "enforce"
    assert resp.json()["fintech_shield_mode_changed_at"] is not None


def test_turning_it_off_needs_a_confirmation_but_watch_does_not(env: Env) -> None:
    assert env.put("off", "observe").status_code == 400
    assert env.put("off", "observe", confirm=True).status_code == 200
    assert env.put("observe", "off").status_code == 200  # turning the safeguard back on needs no confirmation


def test_a_stale_expected_mode_is_a_conflict(env: Env) -> None:
    resp = env.put("off", "enforce", confirm=True)
    assert resp.status_code == 409 and "someone else" in resp.json()["detail"]
    assert env.get().json()["fintech_shield_mode"] == "observe"


def test_holidays_are_stored_sorted_and_validated(env: Env) -> None:
    assert env.put("observe", "observe", ["2026-09-16", "2026-08-31"]).json()["holidays"] == ["2026-08-31", "2026-09-16"]
    assert env.put("observe", "observe", ["2026-08-31", "2026-08-31"]).status_code == 422
    assert env.put("observe", "observe", ["2026-02-30"]).status_code == 422
    assert env.put("observe", "observe", ["0226-08-31"]).status_code == 422
    too_many = [f"2027-01-{d:02d}" for d in range(1, 32)] + [f"2027-03-{d:02d}" for d in range(1, 31)]
    assert env.put("observe", "observe", too_many).status_code == 422
    assert env.get().json()["holidays"] == ["2026-08-31", "2026-09-16"]


def test_unknown_fields_and_values_are_refused(env: Env) -> None:
    assert env.put("block", "observe").status_code == 422
    assert env.client.put(SETTINGS, json={"fintech_shield_mode": "observe", "expected_mode": "observe", "holidays": [], "extra": 1},
                          headers=env.h("admin")).status_code == 422


# --- bindings ----------------------------------------------------------------------------------------------------------------------------

def test_a_tool_can_be_bound_changed_and_bound_again_without_change(env: Env) -> None:
    first = env.bind()
    assert first.status_code == 200 and first.json()["created"] is True
    again = env.bind()
    assert again.json() == {**first.json(), "created": False, "changed": False}
    changed = env.bind(amount_path="payments[*].amount", fixed_currency="MYR")
    assert changed.json()["changed"] is True and changed.json()["id"] == first.json()["id"]
    binding = env.get().json()["bindings"][0]
    assert binding["server_slug"] == "xero" and binding["fixed_currency"] == "MYR" and binding["currency_path"] is None
    assert binding["beneficiary_path"] is None


@pytest.mark.parametrize(
    "body",
    [
        {"amount_path": "payment.amount"},  # no currency source
        {"amount_path": "payment.amount", "currency_path": "c", "fixed_currency": "USD"},  # two currency sources
        {"amount_path": "payment.amount; drop", "fixed_currency": "USD"},
        {"amount_path": "payments[?(@.x)].amount", "fixed_currency": "USD"},  # no filters
        {"amount_path": "..amount", "fixed_currency": "USD"},  # no recursion
        {"amount_path": "amount\n", "fixed_currency": "USD"},  # a trailing newline is not part of the grammar
        {"amount_path": "a" * 257, "fixed_currency": "USD"},
        {"amount_path": "amount", "fixed_currency": "usd"},
        {"amount_path": "amount", "fixed_currency": "USDT"},
        {"amount_path": "amount", "fixed_currency": "USD", "beneficiary_path": "payee vpa"},
        {"amount_path": "amount", "fixed_currency": "USD", "extra": True},
    ],
)
def test_a_binding_outside_the_grammar_is_refused_before_anything_is_stored(env: Env, body: dict[str, Any]) -> None:
    assert env.bind(**body).status_code == 422
    assert env.get().json()["bindings"] == [] and env.audit_actions("mcp_server.fintech_binding_added") == []


@pytest.mark.parametrize("tool", ["pay%20out", "a" * 129, "pay*"])
def test_a_tool_name_outside_the_pattern_is_refused(env: Env, tool: str) -> None:
    assert env.bind(tool=tool).status_code in (404, 422)
    assert env.get().json()["bindings"] == []


def test_a_server_holds_at_most_fifty_bindings(env: Env) -> None:
    for i in range(50):
        assert env.bind(tool=f"tool_{i}").status_code == 200
    resp = env.bind(tool="one_too_many")
    assert resp.status_code == 409 and "50" in resp.json()["detail"]


def test_changing_or_removing_a_binding_while_enforcing_needs_a_confirmation(env: Env) -> None:
    keep = env.bind("transfer_funds").json()["id"]
    other = env.bind("post_payout", amount_path="amount", fixed_currency="USD").json()["id"]
    env.put("enforce", "observe", confirm=True)
    assert env.bind("transfer_funds", amount_path="total", fixed_currency="USD").status_code == 400
    assert env.bind("transfer_funds", amount_path="total", fixed_currency="USD", confirm=True).status_code == 200
    assert env.unbind(other).status_code == 400
    assert env.unbind(other, confirm=True).json() == {"removed": True}
    resp = env.unbind(keep, confirm=True)
    assert resp.status_code == 409 and "last" in resp.json()["detail"]
    assert [b["tool"] for b in env.get().json()["bindings"]] == ["transfer_funds"]


def test_outside_enforce_a_binding_is_removed_without_confirmation(env: Env) -> None:
    binding = env.bind().json()["id"]
    assert env.unbind(binding).json() == {"removed": True}
    assert env.unbind(binding).status_code == 404


# --- audit -------------------------------------------------------------------------------------------------------------------------------

def test_every_change_is_audited_once_and_without_values(env: Env) -> None:
    env.bind()
    env.bind()  # no change: no audit row
    env.bind(amount_path="total", fixed_currency="USD")
    env.put("observe", "observe", ["2026-08-31"], reason="Malaysia holidays")
    env.put("observe", "observe", ["2026-08-31"])  # no change
    binding = env.get().json()["bindings"][0]["id"]
    env.unbind(binding)
    added, changed, removed = (env.audit_actions(f"mcp_server.fintech_binding_{k}") for k in ("added", "changed", "removed"))
    settings = env.audit_actions("organization.fintech_settings_changed")
    assert (len(added), len(changed), len(removed), len(settings)) == (1, 1, 1, 1)
    assert added[0]["details"] == {"tool": "transfer_funds", "binding": binding} and added[0]["target_type"] == "mcp_server"
    assert settings[0]["details"]["holidays"] == 1 and settings[0]["reason"] == "Malaysia holidays"
    for row in added + changed + removed + settings:
        assert "payment.amount" not in str(row) and "payee" not in str(row)


# --- organizations -----------------------------------------------------------------------------------------------------------------------

def test_nothing_crosses_organizations(env: Env) -> None:
    mine = env.bind().json()["id"]
    theirs = env.other_server()
    other = env.other_headers()
    assert env.bind(server_id=theirs).status_code == 404  # my admin, their server
    assert env.bind(headers=other).status_code == 404  # their owner, my server
    assert env.unbind(mine, headers=other).status_code == 404
    assert env.client.put(SETTINGS, json={"fintech_shield_mode": "off", "expected_mode": "observe", "holidays": [], "confirm": True},
                          headers=other).status_code == 200  # their own settings
    assert env.get().json()["fintech_shield_mode"] == "observe"  # mine are untouched
    assert len(env.get().json()["bindings"]) == 1
    assert env.client.get(SETTINGS, headers=other).json()["bindings"] == []


# --- the gateway context -----------------------------------------------------------------------------------------------------------------

def test_the_context_carries_this_servers_bindings_while_the_shield_is_on(env: Env) -> None:
    env.bind()
    env.bind("post_payout", server_id=env.server("ledger"), amount_path="amount", fixed_currency="USD")
    env.put("observe", "observe", ["2026-08-31"])
    fintech = env.context().json()["fintech"]
    assert fintech["mode"] == "observe" and fintech["holidays"] == ["2026-08-31"] and fintech["utc_offset_minutes"] == 480
    assert fintech["bindings"] == [
        {"tool": "transfer_funds", "amount_path": "payment.amount", "currency_path": "payment.currency", "fixed_currency": None,
         "beneficiary_path": "payee.vpa"}
    ]
    assert [b["tool"] for b in env.context("ledger").json()["fintech"]["bindings"]] == ["post_payout"]


def test_an_observe_organization_with_nothing_bound_sends_an_empty_block(env: Env) -> None:
    fintech = env.context().json()["fintech"]
    assert fintech["mode"] == "observe" and fintech["bindings"] == []


def test_the_context_sends_no_block_while_off_or_for_an_unknown_server(env: Env) -> None:
    env.bind()
    env.put("off", "observe", confirm=True)
    assert env.context().json()["fintech"] is None
    env.put("observe", "off")
    assert env.context("nosuchserver").json()["fintech"] is None


@pytest.mark.parametrize("raw, expected", [(None, None), ("off", None), ("observe", "observe"), ("enforce", "enforce"),
                                           ("ENFORCE", "enforce"), ("block", "enforce"), (1, "enforce")])
def test_the_stored_mode_is_read_the_restrictive_way(env: Env, raw: Any, expected: str | None) -> None:
    env.bind()
    env.org()["fintech_shield_mode"] = raw
    fintech = env.context().json()["fintech"]
    assert (fintech["mode"] if fintech else None) == expected


def test_a_malformed_stored_binding_fails_the_lookup_in_enforce_and_sends_no_block_in_observe(env: Env) -> None:
    env.bind()
    env.store.tables["mcp_server_tool_bindings"][0]["amount_path"] = "a; drop"
    assert env.context().status_code == 200 and env.context().json()["fintech"] is None  # observe never refuses
    env.org()["fintech_shield_mode"] = "enforce"
    assert env.context().status_code == 503  # the gateway denies rather than judge payments against nothing


def test_a_failed_binding_lookup_is_a_503_only_in_enforce(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    env.bind()
    original = env.store.table

    def failing(name: str) -> Any:
        if name == "mcp_server_tool_bindings":
            raise RuntimeError("database unavailable")
        return original(name)

    monkeypatch.setattr(env.store, "table", failing)
    assert env.context().status_code == 200 and env.context().json()["fintech"] is None
    env.org()["fintech_shield_mode"] = "enforce"
    assert env.context().status_code == 503


def test_malformed_stored_holidays_are_skipped(env: Env) -> None:
    env.org()["fintech_holidays"] = ["2026-08-31", "not-a-date", "2026-08-31"]
    assert env.context().json()["fintech"]["holidays"] == ["2026-08-31"]


def test_a_stored_path_with_a_trailing_newline_is_malformed(env: Env) -> None:
    # Python's `$` also matches before a final newline; the checks use fullmatch, as the database does.
    env.bind()
    env.store.tables["mcp_server_tool_bindings"][0]["amount_path"] = "amount\n"
    env.org()["fintech_shield_mode"] = "enforce"
    assert env.context().status_code == 503
