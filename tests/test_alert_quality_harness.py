"""Alert-quality metric harness tests."""

from dataclasses import dataclass
from datetime import datetime, timezone
import unittest
from typing import Final, TypedDict, cast

from postgrest.types import JSON

from src.alerter import AlertRuleEngine, evaluate_alert_gate
from src.models import HackSignal, SourceType


@dataclass(frozen=True)
class AlertQualityFixture:
    name: str
    signal: HackSignal
    group: dict[str, object]


class QualityCounts(TypedDict):
    total_signals: int
    active_alerts: int
    review_needed: int
    silent_normal: int
    retrospective_suppressed: int
    active_true_incidents_preserved: int


class DistributionBuckets(TypedDict):
    before: dict[str, int]
    after: dict[str, int]


class AlertQualityMetrics(TypedDict):
    before: QualityCounts
    after: QualityCounts
    confidence_distribution: DistributionBuckets
    severity_distribution: DistributionBuckets


_FIXTURE_TIME: Final[datetime] = datetime(2026, 5, 8, 0, 0, tzinfo=timezone.utc)


def _signal(
    *,
    source_id: str,
    source_url: str,
    source_author: str,
    source_author_tier: int,
    raw_text: str,
    source: SourceType = SourceType.TELEGRAM,
    protocol_name: str | None = None,
    tx_hash: str | None = None,
    llm_is_new_incident: bool | None = None,
    llm_confidence: float | None = None,
) -> HackSignal:
    return HackSignal(
        raw_text=raw_text,
        source=source,
        source_id=source_id,
        source_url=source_url,
        source_author=source_author,
        source_author_tier=source_author_tier,
        published_at=_FIXTURE_TIME,
        protocol_name=protocol_name,
        tx_hash=tx_hash,
        llm_is_new_incident=llm_is_new_incident,
        llm_confidence=llm_confidence,
    )


def _group(**values: object) -> dict[str, object]:
    return {
        "source_types": ["telegram"],
        "best_tier": 1,
        "confidence_score": 0,
        **values,
    }


ALERT_QUALITY_FIXTURES: Final[tuple[AlertQualityFixture, ...]] = (
    AlertQualityFixture(
        name="retrospective_postmortem",
        signal=_signal(
            source_id="tg_retrospective_1",
            source_url="https://t.me/c/retrospective/1",
            source_author="retrospective_channel",
            source_author_tier=1,
            raw_text="OldProtocol postmortem confirms the exploit",
            protocol_name="OldProtocol",
            tx_hash="0x" + "1" * 64,
            llm_is_new_incident=False,
            llm_confidence=0.96,
        ),
        group=_group(
            source_types=["telegram", "twitter"],
            confidence_score=96,
            protocol_name="OldProtocol",
            tx_hash="0x" + "1" * 64,
        ),
    ),
    AlertQualityFixture(
        name="active_true_incident",
        signal=_signal(
            source_id="tg_active_true_1",
            source_url="https://t.me/c/active/1",
            source_author="active_channel",
            source_author_tier=1,
            raw_text="NewProtocol exploit confirmed with live losses",
            protocol_name="NewProtocol",
            tx_hash="0x" + "2" * 64,
            llm_is_new_incident=True,
            llm_confidence=0.98,
        ),
        group=_group(
            confidence_score=80,
            protocol_name="NewProtocol",
            tx_hash="0x" + "2" * 64,
        ),
    ),
    AlertQualityFixture(
        name="active_unknown_with_anchor",
        signal=_signal(
            source_id="tg_active_unknown_1",
            source_url="https://t.me/c/active/2",
            source_author="active_channel",
            source_author_tier=1,
            raw_text="MaybeProtocol incident developing",
            protocol_name="MaybeProtocol",
            tx_hash="0x" + "3" * 64,
            llm_is_new_incident=None,
            llm_confidence=0.89,
        ),
        group=_group(
            confidence_score=72,
            protocol_name="MaybeProtocol",
            tx_hash="0x" + "3" * 64,
        ),
    ),
    AlertQualityFixture(
        name="review_needed_without_anchor",
        signal=_signal(
            source_id="tg_review_1",
            source_url="https://t.me/c/review/1",
            source_author="review_channel",
            source_author_tier=2,
            raw_text="Potential exploit but no anchor yet",
            llm_is_new_incident=None,
            llm_confidence=0.87,
        ),
        group=_group(
            confidence_score=74,
        ),
    ),
    AlertQualityFixture(
        name="silent_normal",
        signal=_signal(
            source_id="tg_silent_1",
            source_url="https://t.me/c/silent/1",
            source_author="silent_channel",
            source_author_tier=3,
            raw_text="Routine maintenance update",
            llm_is_new_incident=None,
            llm_confidence=0.12,
        ),
        group=_group(
            best_tier=3,
            confidence_score=20,
        ),
    ),
)
def _empty_distribution(keys: tuple[str, ...]) -> dict[str, int]:
    return {key: 0 for key in keys}


def build_alert_quality_metrics(
    fixtures: tuple[AlertQualityFixture, ...] = ALERT_QUALITY_FIXTURES,
) -> AlertQualityMetrics:
    engine = AlertRuleEngine()
    before: QualityCounts = {
        "total_signals": 0,
        "active_alerts": 0,
        "review_needed": 0,
        "silent_normal": 0,
        "retrospective_suppressed": 0,
        "active_true_incidents_preserved": 0,
    }
    after: QualityCounts = {
        "total_signals": 0,
        "active_alerts": 0,
        "review_needed": 0,
        "silent_normal": 0,
        "retrospective_suppressed": 0,
        "active_true_incidents_preserved": 0,
    }

    for fixture in fixtures:
        before["total_signals"] += 1
        after["total_signals"] += 1

        group = cast(dict[str, JSON], fixture.group)
        decision = engine.evaluate(group)
        gate = evaluate_alert_gate(fixture.signal, group)
        has_identity_anchor = any(bool(fixture.group.get(field)) for field in ("protocol_name", "tx_hash", "attacker_address"))

        if decision.should_alert and has_identity_anchor:
            before["active_alerts"] += 1
        elif decision.should_alert:
            before["review_needed"] += 1
        else:
            before["silent_normal"] += 1

        if fixture.signal.llm_is_new_incident is False and (fixture.signal.llm_confidence or 0) >= 0.85:
            after["retrospective_suppressed"] += 1
            continue

        if fixture.signal.llm_is_new_incident is True or (
            fixture.signal.llm_is_new_incident is None and has_identity_anchor
        ):
            if decision.should_alert and not gate.should_block_alert:
                after["active_alerts"] += 1
                after["active_true_incidents_preserved"] += 1
            elif decision.should_alert and gate.status == "ambiguous":
                after["review_needed"] += 1
            else:
                after["silent_normal"] += 1
            continue

        if decision.should_alert and gate.status == "ambiguous":
            after["review_needed"] += 1
        else:
            after["silent_normal"] += 1

    confidence_distribution: DistributionBuckets = {
        "before": {
            "high": before["active_alerts"],
            "medium": before["review_needed"],
            "low": before["silent_normal"],
        },
        "after": {
            "high": after["active_alerts"] + after["retrospective_suppressed"],
            "medium": after["review_needed"],
            "low": after["silent_normal"],
        },
    }
    severity_distribution: DistributionBuckets = {
        "before": _empty_distribution(("critical", "high", "medium", "low")),
        "after": _empty_distribution(("critical", "high", "medium", "low")),
    }
    for fixture in fixtures:
        confidence_score = int(cast(int, fixture.group.get("confidence_score") or 0))
        if confidence_score >= 95:
            band = "critical"
        elif confidence_score >= 80:
            band = "high"
        elif confidence_score >= 74:
            band = "medium"
        else:
            band = "low"
        severity_distribution["before"][band] += 1
        severity_distribution["after"][band] += 1

    return {
        "before": before,
        "after": after,
        "confidence_distribution": confidence_distribution,
        "severity_distribution": severity_distribution,
    }


def _render_distribution(label: str, metrics: dict[str, int]) -> str:
    return f"{label} | " + ", ".join(f"{name}={count}" for name, count in metrics.items())


def render_alert_quality_metrics_table(metrics: AlertQualityMetrics) -> str:
    lines = [
        "phase | total_signals | active_alerts | review_needed | silent_normal | retrospective_suppressed | active_true_incidents_preserved",
        "--- | --- | --- | --- | --- | --- | ---",
        f"before | {metrics['before']['total_signals']} | {metrics['before']['active_alerts']} | {metrics['before']['review_needed']} | {metrics['before']['silent_normal']} | {metrics['before']['retrospective_suppressed']} | {metrics['before']['active_true_incidents_preserved']}",
        f"after | {metrics['after']['total_signals']} | {metrics['after']['active_alerts']} | {metrics['after']['review_needed']} | {metrics['after']['silent_normal']} | {metrics['after']['retrospective_suppressed']} | {metrics['after']['active_true_incidents_preserved']}",
    ]
    confidence = metrics["confidence_distribution"]
    severity = metrics["severity_distribution"]
    lines.extend(
        [
            "",
            "confidence_distribution",
            _render_distribution("before", confidence["before"]),
            _render_distribution("after", confidence["after"]),
            "",
            "severity_distribution",
            _render_distribution("before", severity["before"]),
            _render_distribution("after", severity["after"]),
        ]
    )
    return "\n".join(lines)


class AlertQualityMetricHarnessTest(unittest.TestCase):
    def test_before_after_metrics_are_deterministic(self) -> None:
        metrics = build_alert_quality_metrics(ALERT_QUALITY_FIXTURES)

        self.assertEqual(
            metrics["before"],
            {
                "total_signals": 5,
                "active_alerts": 3,
                "review_needed": 1,
                "silent_normal": 1,
                "retrospective_suppressed": 0,
                "active_true_incidents_preserved": 0,
            },
        )
        self.assertEqual(
            metrics["after"],
            {
                "total_signals": 5,
                "active_alerts": 2,
                "review_needed": 1,
                "silent_normal": 1,
                "retrospective_suppressed": 1,
                "active_true_incidents_preserved": 2,
            },
        )

    def test_distribution_metrics_are_deterministic(self) -> None:
        metrics = build_alert_quality_metrics(ALERT_QUALITY_FIXTURES)

        self.assertEqual(
            metrics["confidence_distribution"],
            {
                "before": {"high": 3, "medium": 1, "low": 1},
                "after": {"high": 3, "medium": 1, "low": 1},
            },
        )
        self.assertEqual(
            metrics["severity_distribution"],
            {
                "before": {"critical": 1, "high": 1, "medium": 1, "low": 2},
                "after": {"critical": 1, "high": 1, "medium": 1, "low": 2},
            },
        )

    def test_retrospective_suppression_and_active_recall_are_preserved(self) -> None:
        metrics = build_alert_quality_metrics(ALERT_QUALITY_FIXTURES)["after"]

        self.assertEqual(metrics["retrospective_suppressed"], 1)
        self.assertEqual(metrics["active_true_incidents_preserved"], 2)

    def test_metric_table_renders_exact_integers(self) -> None:
        table = render_alert_quality_metrics_table(build_alert_quality_metrics(ALERT_QUALITY_FIXTURES))

        self.assertIn(
            "phase | total_signals | active_alerts | review_needed | silent_normal | retrospective_suppressed | active_true_incidents_preserved",
            table,
        )
        self.assertIn("before | 5 | 3 | 1 | 1 | 0 | 0", table)
        self.assertIn("after | 5 | 2 | 1 | 1 | 1 | 2", table)


if __name__ == "__main__":
    _ = unittest.main()
