"""Focused integration coverage for grouped incident scoring and alert gates."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import cast
from uuid import uuid4

from postgrest.types import JSON
from supabase import Client

from src.alerter import AlertDecision, AlertGateDecision, AlertRuleEngine, evaluate_alert_gate
from src.grouper import IncidentGrouper
from src.models import HackSignal, SourceType
from src.scorer import calculate_confidence, calculate_corroboration, calculate_severity
from tests.test_grouper import FakeSupabaseClient


def _as_client(fake: FakeSupabaseClient) -> Client:
    return cast(Client, cast(object, fake))


def _signal(
    *,
    protocol_name: str = "TestProtocol",
    source: SourceType = SourceType.TWITTER,
    source_author: str = "researcher",
    source_author_tier: int = 2,
    published_at: datetime | None = None,
    source_url: str | None = None,
    tx_hash: str | None = None,
    loss_usd: float | None = None,
    attacker_address: str | None = None,
    chain: str | None = None,
    llm_is_new_incident: bool | None = True,
    llm_confidence: float | None = 0.99,
) -> HackSignal:
    return HackSignal(
        raw_text=f"{protocol_name} exploit signal from {source_author}",
        source=source,
        source_id=f"{source.value}:{uuid4()}",
        source_url=source_url or f"https://example.com/{source.value}/{uuid4()}",
        source_author=source_author,
        source_author_tier=source_author_tier,
        published_at=published_at or datetime.now(timezone.utc),
        protocol_name=protocol_name,
        chain=chain,
        loss_usd=loss_usd,
        tx_hash=tx_hash,
        attacker_address=attacker_address,
        llm_is_new_incident=llm_is_new_incident,
        llm_confidence=llm_confidence,
    )


def _group_from(signals: list[HackSignal]) -> dict[str, JSON]:
    client = FakeSupabaseClient()
    grouper = IncidentGrouper(_as_client(client))

    for signal in signals:
        assert grouper.match_or_create(signal) is not None

    groups = client.groups()
    assert len(groups) == 1
    return cast(dict[str, JSON], groups[0])


def _score_group(group: dict[str, JSON], *, llm_is_new_incident: bool | None = True) -> dict[str, JSON]:
    scored: dict[str, JSON] = dict(group)
    scored["llm_is_new_incident"] = llm_is_new_incident
    scored["corroboration_score"] = calculate_corroboration(scored)
    scored["confidence_score"] = calculate_confidence(scored)
    severity_score, severity_label = calculate_severity(scored)
    scored["severity_score"] = severity_score
    scored["severity_label"] = severity_label
    return scored


def _score_signals(signals: list[HackSignal], *, llm_is_new_incident: bool | None = True) -> dict[str, JSON]:
    return _score_group(_group_from(signals), llm_is_new_incident=llm_is_new_incident)


def _summary(
    scenario: str,
    group: dict[str, JSON],
    gate: AlertGateDecision,
    decision: AlertDecision,
) -> dict[str, JSON]:
    return {
        "scenario": scenario,
        "group": {
            "source_types": group.get("source_types"),
            "source_authors": group.get("source_authors"),
            "source_author_count": group.get("source_author_count"),
            "tier1_author_count": group.get("tier1_author_count"),
            "tier2_author_count": group.get("tier2_author_count"),
            "signal_count": group.get("signal_count"),
            "protocol_name": group.get("protocol_name"),
            "tx_hash": group.get("tx_hash"),
            "first_seen_at": group.get("first_seen_at"),
        },
        "scores": {
            "confidence_score": group.get("confidence_score"),
            "corroboration_score": group.get("corroboration_score"),
            "severity_score": group.get("severity_score"),
            "severity_label": group.get("severity_label"),
        },
        "gate": {"status": gate.status, "reason": gate.reason},
        "alert_decision": {
            "should_alert": decision.should_alert,
            "alert_level": decision.alert_level,
            "reason": decision.reason,
            "severity_score": decision.severity_score,
            "severity_label": decision.severity_label,
        },
    }


def _emit(
    scenario: str,
    group: dict[str, JSON],
    gate: AlertGateDecision,
    decision: AlertDecision,
) -> None:
    print(json.dumps(_summary(scenario, group, gate, decision), sort_keys=True))


def test_same_platform_multi_author_active_incident_is_bounded() -> None:
    tx = "0x" + "a" * 64
    published_at = datetime(2026, 5, 8, 12, 0, tzinfo=timezone.utc)
    group = _score_signals([
        _signal(source_author="alice_sec", tx_hash=tx, published_at=published_at),
        _signal(source_author="bob_defi", tx_hash=tx, published_at=published_at),
        _signal(source_author="carol_chain", tx_hash=tx, published_at=published_at),
    ])
    gate = evaluate_alert_gate(_signal(source_author="carol_chain", tx_hash=tx), group)
    decision = AlertRuleEngine().evaluate(group)

    assert group["source_types"] == ["twitter"]
    assert group["source_author_count"] == 3
    assert group["corroboration_score"] == 15
    assert group["severity_label"] == "high"
    assert decision.alert_level == "silent"
    assert decision.severity_score == group["severity_score"]
    assert decision.severity_label == group["severity_label"]
    assert gate.status == "allow"
    _emit("same_platform_multi_author_active_bounded", group, gate, decision)


def test_same_author_repeats_do_not_inflate_author_count_or_corroboration() -> None:
    tx = "0x" + "b" * 64
    group = _score_signals([
        _signal(source_author="same_author", tx_hash=tx),
        _signal(source_author="same_author", tx_hash=tx),
        _signal(source_author="same_author", tx_hash=tx),
    ])
    gate = evaluate_alert_gate(_signal(source_author="same_author", tx_hash=tx), group)
    decision = AlertRuleEngine().evaluate(group)

    assert group["signal_count"] == 3
    assert group["source_author_count"] == 1
    assert group["corroboration_score"] == 0
    assert gate.status == "allow"
    _emit("same_author_repeat_no_inflation", group, gate, decision)


def test_cross_platform_confirmation_stays_separate_from_same_platform_authors() -> None:
    tx = "0x" + "c" * 64
    group = _score_signals([
        _signal(source=SourceType.TWITTER, source_author="twitter_sec", tx_hash=tx),
        _signal(source=SourceType.TELEGRAM, source_author="telegram_sec", tx_hash=tx),
    ])
    gate = evaluate_alert_gate(_signal(source=SourceType.TELEGRAM, source_author="telegram_sec", tx_hash=tx), group)
    decision = AlertRuleEngine().evaluate(group)

    assert set(cast(list[str], group["source_types"])) == {"twitter", "telegram"}
    assert group["source_author_count"] == 2
    assert group["corroboration_score"] == 0
    assert decision.should_alert
    assert decision.reason.startswith("cross_source")
    assert gate.status == "allow"
    _emit("cross_platform_confirmation_separate", group, gate, decision)


def test_retrospective_report_suppresses_without_fresh_anchor() -> None:
    tx = "0x" + "d" * 64
    signal = _signal(
        protocol_name="Uniswap",
        tx_hash=tx,
        loss_usd=2_000_000,
        source_author="postmortem_team",
        llm_is_new_incident=False,
        llm_confidence=0.96,
        published_at=datetime(2026, 5, 8, 0, 15, tzinfo=timezone.utc),
        source_url="https://x.com/security/status/111",
    )
    group = _score_signals([signal], llm_is_new_incident=False)
    gate = evaluate_alert_gate(signal, group)
    decision = AlertRuleEngine().evaluate(group)

    assert "source_url" not in group
    assert "source_urls" not in group
    assert gate.status == "suppressed"
    assert gate.reason == "llm_non_new_no_fresh_anchor"
    assert group["severity_score"] == 30
    assert group["severity_label"] == "low"
    _emit("retrospective_suppressed_no_fresh_anchor", group, gate, decision)


def test_xai_or_no_llm_unknown_newness_fails_open_to_normal_alert_evaluation() -> None:
    tx = "0x" + "e" * 64
    signal = _signal(
        protocol_name="Aave",
        source_author="tier1_alerts",
        source_author_tier=1,
        tx_hash=tx,
        loss_usd=1_500_000,
        llm_is_new_incident=None,
        llm_confidence=None,
    )
    group = _score_signals([signal], llm_is_new_incident=None)
    gate = evaluate_alert_gate(signal, group)
    decision = AlertRuleEngine().evaluate(group)

    assert gate.status == "allow"
    assert gate.reason == ""
    assert decision.should_alert
    assert decision.reason == "tier1_high_confidence(80)"
    assert decision.severity_score == group["severity_score"]
    assert decision.severity_label == group["severity_label"]
    _emit("xai_no_llm_fail_open", group, gate, decision)


def test_repeat_protocol_fresh_incident_protects_against_protocol_name_suppression() -> None:
    old_context: dict[str, JSON] = {
        "protocol_name": "Uniswap",
        "tx_hash": "0x" + "1" * 64,
        "first_seen_at": "2026-05-08T00:00:00+00:00",
        "source_authors": ["telegram:oldreporter:1"],
        "source_url": "https://t.me/c/1/100",
    }
    fresh_at = datetime(2026, 5, 8, 12, 0, tzinfo=timezone.utc)
    new_tx = "0x" + "f" * 64
    fresh_signals = [
        _signal(
            protocol_name="Uniswap",
            source_author="new_reporter_a",
            source_author_tier=1,
            tx_hash=new_tx,
            published_at=fresh_at,
            source_url="https://x.com/new_reporter_a/status/222",
            llm_is_new_incident=False,
        ),
        _signal(
            protocol_name="Uniswap",
            source_author="new_reporter_b",
            source_author_tier=2,
            tx_hash=new_tx,
            published_at=fresh_at,
            source_url="https://x.com/new_reporter_b/status/223",
            llm_is_new_incident=False,
        ),
    ]
    fresh_group = _score_signals(fresh_signals, llm_is_new_incident=True)
    gate = evaluate_alert_gate(fresh_signals[1], old_context)
    decision = AlertRuleEngine().evaluate(fresh_group)

    assert gate.status == "allow"
    assert gate.reason == ""
    assert fresh_group["protocol_name"] == "Uniswap"
    assert fresh_group["tx_hash"] == new_tx
    assert fresh_group["source_author_count"] == 2
    assert fresh_group["corroboration_score"] == 10
    assert decision.severity_score == fresh_group["severity_score"]
    assert decision.severity_label == fresh_group["severity_label"]
    _emit("repeat_protocol_fresh_incident_protected", fresh_group, gate, decision)
