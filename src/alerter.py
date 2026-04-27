"""Alert Rule Engine — Incident 그룹 평가 후 알림 레벨 판정

Rules (우선순위):
  Rule 1: 교차 채널 (source_types 2+ 종류) → critical
  Rule 2: 단일 소스 + Tier 1 + confidence ≥ 70 → critical
  Rule 3: 그 외 → silent
"""
from dataclasses import dataclass
from typing import Literal


@dataclass
class AlertDecision:
    should_alert: bool
    alert_level: Literal["critical", "follow_up", "silent"]
    reason: str


class AlertRuleEngine:
    """lumos_incident_groups row를 평가하여 알림 여부 결정"""

    def evaluate(self, group: dict) -> AlertDecision:
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
        source_types = group.get("source_types") or []
        unique_sources = set(source_types)
        confidence = group.get("confidence_score") or 0
        best_tier = group.get("best_tier") or 3

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
