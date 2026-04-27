"""Alert Deduplicator — 그룹 기반 중복 알림 방지

판정:
  - first_alert: 해당 incident_group의 첫 알림
  - follow_up: 기존 알림 있으나 새 핵심정보(tx_hash, loss_usd, attacker_address) 추가됨
  - silent: 이미 알림 발송 + 새 정보 없음
"""
from dataclasses import dataclass, field
from typing import Literal

from supabase import Client


AlertAction = Literal["first_alert", "follow_up", "silent"]

# follow_up 판단에 사용할 핵심 필드
_KEY_FIELDS = ("tx_hash", "loss_usd", "attacker_address")


@dataclass
class DeduplicatorResult:
    """Dedup 판정 결과 + 실제 새로 추가된 필드 목록"""
    action: AlertAction
    new_fields: list[str] = field(default_factory=list)


class AlertDeduplicator:
    """lumos_hack_alerts 이력 기반 중복 체크"""

    def __init__(self, client: Client):
        self.client = client
        self.table = "lumos_hack_alerts"

    def check(self, group_id: str, group: dict) -> DeduplicatorResult:
        """
        Args:
            group_id: incident_group UUID
            group: lumos_incident_groups row (dict) — 현재 그룹 상태
        Returns:
            DeduplicatorResult with action and new_fields
        """
        try:
            return self._do_check(group_id, group)
        except Exception as e:
            # Critical 3: 쿼리 실패 시 first_alert으로 fallback (알림 누락보다 중복이 안전)
            print(f"  Dedup query failed, fallback to first_alert: {e}")
            return DeduplicatorResult(action="first_alert")

    def _do_check(self, group_id: str, group: dict) -> DeduplicatorResult:
        """실제 dedup 로직 (예외는 check()에서 처리)"""
        # 기존 알림 조회
        existing = (
            self.client.table(self.table)
            .select("metadata")
            .eq("incident_group_id", group_id)
            .order("created_at", desc=True)
            .limit(5)
            .execute()
        )

        if not existing.data:
            return DeduplicatorResult(action="first_alert")

        # 기존 알림들의 metadata에서 핵심 필드 수집
        known_fields: set[str] = set()
        for alert in existing.data:
            meta = alert.get("metadata") or {}
            for f in _KEY_FIELDS:
                if meta.get(f):
                    known_fields.add(f)

        # Critical 4: 현재 그룹에서 실제로 새로 추가된 핵심 필드만 수집
        new_fields: list[str] = []
        for f in _KEY_FIELDS:
            if group.get(f) and f not in known_fields:
                new_fields.append(f)

        if new_fields:
            return DeduplicatorResult(action="follow_up", new_fields=new_fields)

        return DeduplicatorResult(action="silent")
