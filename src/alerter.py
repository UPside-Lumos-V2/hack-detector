"""Alert Rule Engine — Incident 그룹 평가 후 알림 레벨 판정

Rules (우선순위):
  Rule 1: 교차 채널 (source_types 2+ 종류) → critical
  Rule 2: 단일 소스 + Tier 1 + confidence ≥ 70 → critical
  Rule 3: 그 외 → silent
"""
from dataclasses import dataclass
from typing import Literal

from postgrest.types import JSON

from src.models import HackSignal


@dataclass
class AlertDecision:
    should_alert: bool
    alert_level: Literal["critical", "follow_up", "silent"]
    reason: str


@dataclass
class AlertGateDecision:
    status: Literal["allow", "ambiguous", "quarantined"]
    reason: str

    @property
    def should_block_alert(self) -> bool:
        return self.status != "allow"


_IDENTITY_ANCHORS = ("protocol_name", "tx_hash", "attacker_address")
_HIGH_CONFIDENCE_LLM = 0.85


def _string_list(value: JSON | None) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _int_value(value: JSON | None, default: int) -> int:
    if isinstance(value, bool):
        return default
    return int(value) if isinstance(value, int | float) else default


def evaluate_signal_quarantine(signal: HackSignal) -> AlertGateDecision:
    """신호 자체만 보고 알림 전 격리할지 판단한다."""
    if signal.llm_is_hack is False and (signal.llm_confidence or 0) >= _HIGH_CONFIDENCE_LLM:
        return AlertGateDecision("quarantined", "llm_not_hack_high_confidence")
    return AlertGateDecision("allow", "")


def evaluate_alert_gate(signal: HackSignal, group: dict[str, JSON]) -> AlertGateDecision:
    """알림 직전 최소 식별 정보가 있는지 확인한다."""
    signal_gate = evaluate_signal_quarantine(signal)
    if signal_gate.should_block_alert:
        return signal_gate

    if not any(group.get(field) for field in _IDENTITY_ANCHORS):
        return AlertGateDecision("ambiguous", "missing_identity_anchor")

    return AlertGateDecision("allow", "")


class AlertRuleEngine:
    """lumos_incident_groups row를 평가하여 알림 여부 결정"""

    def evaluate(self, group: dict[str, JSON]) -> AlertDecision:
        """
        Args:
            group: lumos_incident_groups row (dict)
                - source_types: ['twitter', 'telegram']
                - confidence_score: int
                - signal_count: int
                - best_tier: int (없으면 3 기본)
        Returns:
            AlertDecision
        """
        source_types = _string_list(group.get("source_types"))
        unique_sources = set(source_types)
        confidence = _int_value(group.get("confidence_score"), 0)
        best_tier = _int_value(group.get("best_tier"), 3)

        # Rule 1: 교차 채널 2+ 종류 → 무조건 critical
        if len(unique_sources) >= 2:
            return AlertDecision(
                should_alert=True,
                alert_level="critical",
                reason=f"cross_source({'/'.join(sorted(unique_sources))})",
            )

        # Rule 2: 단일 소스 + Tier 1 + confidence ≥ 70
        if best_tier == 1 and confidence >= 70:
            return AlertDecision(
                should_alert=True,
                alert_level="critical",
                reason=f"tier1_high_confidence({confidence})",
            )

        # Rule 3: 그 외 → silent
        return AlertDecision(
            should_alert=False,
            alert_level="silent",
            reason="below_threshold",
        )
