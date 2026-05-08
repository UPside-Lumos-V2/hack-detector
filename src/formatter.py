"""Alert Formatter — 구조화된 알림 메시지 생성

5개 메타데이터 필드: protocol_name, chain, tx_hash, loss_usd, attacker_address
알림 메시지에 식별 현황 (N/5) 포함.
"""
from dataclasses import dataclass, field

from postgrest.types import JSON


_META_FIELDS = ("protocol_name", "chain", "tx_hash", "loss_usd", "attacker_address")
_FIELD_LABELS = {
    "protocol_name": "protocol",
    "chain": "chain",
    "tx_hash": "tx_hash",
    "loss_usd": "loss_usd",
    "attacker_address": "attacker",
}


def _format_usd(n: float) -> str:
    if n >= 1_000_000_000:
        return f"${n / 1_000_000_000:.1f}B"
    if n >= 1_000_000:
        return f"${n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"${n / 1_000:.0f}K"
    return f"${n:,.0f}"


def _string_value(value: JSON | None, default: str) -> str:
    return value if isinstance(value, str) else default


def _float_value(value: JSON | None) -> float | None:
    if isinstance(value, bool):
        return None
    return float(value) if isinstance(value, int | float) else None


def _string_list(value: JSON | None) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _metadata(group: dict[str, JSON]) -> dict[str, JSON]:
    metadata: dict[str, JSON] = {}
    for f in _META_FIELDS:
        value = group.get(f)
        if value:
            metadata[f] = value
    return metadata


def _meta_summary(group: dict[str, JSON]) -> str:
    """메타데이터 식별 현황 문자열 생성: '4/5 식별 (protocol ✓ chain ✓ ...)'"""
    detected: list[str] = []
    for f in _META_FIELDS:
        label = _FIELD_LABELS[f]
        if group.get(f):
            detected.append(f"{label} ✓")
        else:
            detected.append(f"{label} ✗")
    count = sum(1 for f in _META_FIELDS if group.get(f))
    return f"{count}/5 식별 ({' '.join(detected)})"


@dataclass
class AlertMessage:
    title: str
    body: str
    alert_level: str
    alert_action: str
    incident_group_id: str
    source_count: int
    metadata: dict[str, JSON] = field(default_factory=dict)


class AlertFormatter:
    """Incident 그룹 데이터 → 알림 메시지"""

    def format_first_alert(
        self, group_id: str, group: dict[str, JSON], *, source_url: str | None = None,
    ) -> AlertMessage:
        protocol = _string_value(group.get("protocol_name"), "Unknown Protocol")
        loss_usd = _float_value(group.get("loss_usd"))
        loss = _format_usd(loss_usd) if loss_usd else "unknown"
        source_types = _string_list(group.get("source_types"))
        source_count = len(set(source_types))
        confidence = group.get("confidence_score") or 0
        meta_line = _meta_summary(group)

        title = f"{protocol} hacked \u2014 {loss} lost"
        body = (
            f"{title}\n"
            f"\u251c\u2500 \uba54\ud0c0\ub370\uc774\ud130: {meta_line}\n"
            f"\u251c\u2500 \uc18c\uc2a4: {source_count}\uac1c ({', '.join(sorted(set(source_types)))})\n"
            f"\u251c\u2500 Confidence: {confidence}\n"
        )

        tx_hash = group.get("tx_hash")
        if isinstance(tx_hash, str) and tx_hash:
            body += f"\u251c\u2500 Tx: {tx_hash[:20]}...\n"
        if group.get("chain"):
            body += f"\u251c\u2500 Chain: {group['chain']}\n"
        if source_url:
            body += f"\u251c\u2500 Source: {source_url}\n"
        body += f"\u2514\u2500 Group: {group_id[:8]}..."

        return AlertMessage(
            title=title,
            body=body,
            alert_level="critical",
            alert_action="first_alert",
            incident_group_id=group_id,
            source_count=source_count,
            metadata=_metadata(group),
        )

    def format_follow_up(
        self, group_id: str, group: dict[str, JSON], new_fields: list[str],
        *, source_url: str | None = None,
    ) -> AlertMessage:
        protocol = _string_value(group.get("protocol_name"), "Unknown Protocol")
        meta_line = _meta_summary(group)
        new_info = ", ".join(new_fields)

        title = f"{protocol} \uc5c5\ub370\uc774\ud2b8 \u2014 +{len(new_fields)} \uc0c8 \uc815\ubcf4"
        body = (
            f"{title}\n"
            f"\u251c\u2500 \uba54\ud0c0\ub370\uc774\ud130: {meta_line}\n"
            f"\u251c\u2500 \uc0c8 \uc815\ubcf4: {new_info}\n"
        )
        for f in new_fields:
            val = group.get(f)
            if val:
                body += f"\u251c\u2500 {_FIELD_LABELS.get(f, f)}: {val}\n"
        if source_url:
            body += f"\u251c\u2500 Source: {source_url}\n"
        body += f"\u2514\u2500 Group: {group_id[:8]}..."

        source_types = _string_list(group.get("source_types"))
        return AlertMessage(
            title=title,
            body=body,
            alert_level="follow_up",
            alert_action="follow_up",
            incident_group_id=group_id,
            source_count=len(set(source_types)),
            metadata=_metadata(group),
        )
