"""Alert Formatter — 구조화된 알림 메시지 생성

5개 메타데이터 필드: protocol_name, chain, tx_hash, loss_usd, attacker_address
알림 메시지에 식별 현황 (N/5) 포함.
"""
from dataclasses import dataclass, field


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


def _meta_summary(group: dict) -> str:
    """메타데이터 식별 현황 문자열 생성: '4/5 식별 (protocol ✓ chain ✓ ...)'"""
    detected = []
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
    metadata: dict = field(default_factory=dict)


class AlertFormatter:
    """Incident 그룹 데이터 → 알림 메시지"""

    def format_first_alert(
        self, group_id: str, group: dict, *, source_url: str | None = None,
    ) -> AlertMessage:
        protocol = group.get("protocol_name") or "Unknown Protocol"
        loss = _format_usd(group["loss_usd"]) if group.get("loss_usd") else "unknown"
        source_types = group.get("source_types") or []
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

        if group.get("tx_hash"):
            body += f"\u251c\u2500 Tx: {group['tx_hash'][:20]}...\n"
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
            metadata={
                f: group.get(f) for f in _META_FIELDS if group.get(f)
            },
        )

    def format_follow_up(
        self, group_id: str, group: dict, new_fields: list[str],
        *, source_url: str | None = None,
    ) -> AlertMessage:
        protocol = group.get("protocol_name") or "Unknown Protocol"
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

        source_types = group.get("source_types") or []
        return AlertMessage(
            title=title,
            body=body,
            alert_level="follow_up",
            alert_action="follow_up",
            incident_group_id=group_id,
            source_count=len(set(source_types)),
            metadata={
                f: group.get(f) for f in _META_FIELDS if group.get(f)
            },
        )
