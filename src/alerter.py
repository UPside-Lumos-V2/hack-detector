"""Alert Rule Engine — Incident 그룹 평가 후 알림 레벨 판정

Rules (우선순위):
  Rule 1: 교차 채널 (source_types 2+ 종류) → critical
  Rule 2: 단일 소스 + Tier 1 + confidence ≥ 70 → critical
  Rule 3: 그 외 → silent
"""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal

from postgrest.types import JSON

from src.models import HackSignal


@dataclass
class AlertDecision:
    should_alert: bool
    alert_level: Literal["critical", "follow_up", "silent"]
    reason: str
    severity_score: int | None = None
    severity_label: str | None = None


@dataclass
class AlertGateDecision:
    status: Literal["allow", "ambiguous", "quarantined", "suppressed"]
    reason: str

    @property
    def should_block_alert(self) -> bool:
        return self.status != "allow"


_IDENTITY_ANCHORS = ("protocol_name", "tx_hash", "attacker_address")
_HIGH_CONFIDENCE_LLM = 0.85
_FRESH_CLUSTER_WINDOW = timedelta(hours=6)


def _string_list(value: JSON | None) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _int_value(value: JSON | None, default: int) -> int:
    if isinstance(value, bool):
        return default
    return int(value) if isinstance(value, int | float) else default


def _float_value(value: JSON | None) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    return None


def _string_value(value: JSON | None) -> str | None:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped if stripped else None
    return None


def _optional_int_value(value: JSON | None) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return int(value)
    return None


def _datetime_value(value: JSON | None) -> datetime | None:
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    normalized = raw.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _author_key(source: str, author: str | None) -> str | None:
    if not author:
        return None
    normalized = author.strip().lower()
    if not normalized:
        return None
    return f"{source}:{normalized}"


def _author_keys_from_group(value: JSON | None) -> set[str]:
    keys: set[str] = set()
    for entry in _string_list(value):
        tier_idx = entry.rfind(":")
        key = entry if tier_idx < 0 else entry[:tier_idx]
        if key:
            keys.add(key)
    return keys


def _has_emitted_active_alert(group: dict[str, JSON]) -> bool:
    for flag_key in ("has_active_alert", "active_alert_emitted"):
        if group.get(flag_key) is True:
            return True

    alert_status = _string_value(group.get("alert_status"))
    if alert_status in {"alerted", "follow_up"}:
        return True

    return _int_value(group.get("alert_count"), 0) > 0


def _has_fresh_incident_anchor(signal: HackSignal, group: dict[str, JSON]) -> bool:
    group_tx = _string_value(group.get("tx_hash"))
    if signal.tx_hash and signal.tx_hash != group_tx:
        return True

    group_attacker = _string_value(group.get("attacker_address"))
    if signal.attacker_address and signal.attacker_address != group_attacker:
        return True

    group_loss = _float_value(group.get("loss_usd"))
    if signal.loss_usd is not None and (group_loss is None or abs(signal.loss_usd - group_loss) > 0):
        return True

    known_urls = set(_string_list(group.get("source_urls")))
    group_source_url = _string_value(group.get("source_url"))
    if group_source_url:
        known_urls.add(group_source_url)
    if known_urls and signal.source_url and signal.source_url not in known_urls:
        return True

    group_seen_at = _datetime_value(group.get("published_at")) or _datetime_value(group.get("first_seen_at"))
    if group_seen_at and signal.published_at >= group_seen_at + _FRESH_CLUSTER_WINDOW:
        return True

    group_authors = _author_keys_from_group(group.get("source_authors"))
    incoming_author = _author_key(signal.source.value, signal.source_author)
    if incoming_author and incoming_author not in group_authors and len(group_authors | {incoming_author}) >= 2:
        return True

    return False


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

    if (
        signal.llm_is_new_incident is False
        and (signal.llm_confidence or 0.0) >= _HIGH_CONFIDENCE_LLM
        and not _has_emitted_active_alert(group)
        and not _has_fresh_incident_anchor(signal, group)
    ):
        return AlertGateDecision("suppressed", "llm_non_new_no_fresh_anchor")

    if not any(group.get(field) for field in _IDENTITY_ANCHORS):
        return AlertGateDecision("ambiguous", "missing_identity_anchor")

    return AlertGateDecision("allow", "")


def _severity_fields(group: dict[str, JSON]) -> tuple[int | None, str | None]:
    return _optional_int_value(group.get("severity_score")), _string_value(group.get("severity_label"))


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
        severity_score, severity_label = _severity_fields(group)

        # Rule 1: 교차 채널 2+ 종류 → 무조건 critical
        if len(unique_sources) >= 2:
            return AlertDecision(
                should_alert=True,
                alert_level="critical",
                reason=f"cross_source({'/'.join(sorted(unique_sources))})",
                severity_score=severity_score,
                severity_label=severity_label,
            )

        # Rule 2: 단일 소스 + Tier 1 + confidence ≥ 70
        if best_tier == 1 and confidence >= 70:
            return AlertDecision(
                should_alert=True,
                alert_level="critical",
                reason=f"tier1_high_confidence({confidence})",
                severity_score=severity_score,
                severity_label=severity_label,
            )

        # Rule 3: 그 외 → silent
        return AlertDecision(
            should_alert=False,
            alert_level="silent",
            reason="below_threshold",
            severity_score=severity_score,
            severity_label=severity_label,
        )
