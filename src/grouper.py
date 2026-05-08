"""Incident Grouper — 같은 해킹 사건 신호를 하나의 그룹으로 묶기

매칭 규칙 (우선순위):
1. tx_hash 완전 일치          → 동일 트랜잭션 (100% 확신)
2. protocol_name + 2시간 내   → 같은 프로토콜 연속 보고
3. attacker_address + 6시간 내 → 같은 공격자 연속 보고
"""
from datetime import datetime, timedelta, timezone
from typing import Any, cast

from supabase import Client

from src.models import HackSignal


# 매칭 시간 윈도우
PROTOCOL_WINDOW = timedelta(hours=2)
ATTACKER_WINDOW = timedelta(hours=6)


# ── Author provenance helpers ──────────────────────────────────────────────────

def _author_key(signal: HackSignal) -> str:
    author = (signal.source_author or "").lower().strip()
    if not author:
        return ""
    return f"{signal.source.value}:{author}"


def _merge_authors(existing: list[str], signal: HackSignal) -> list[str]:
    key = _author_key(signal)
    if not key:
        return existing

    result: list[str] = []
    found = False
    for entry in existing:
        # Use rfind to avoid mismatching ':' inside the author segment itself
        colon_pos = entry.rfind(":")
        if colon_pos != -1 and entry[:colon_pos] == key:
            stored_tier_str = entry[colon_pos + 1:]
            current_tier = int(stored_tier_str) if stored_tier_str.isdigit() else 9
            best_tier = min(current_tier, signal.source_author_tier)
            result.append(f"{key}:{best_tier}")
            found = True
        else:
            result.append(entry)

    if not found:
        result.append(f"{key}:{signal.source_author_tier}")

    return result


def _tier_counts(authors: list[str]) -> tuple[int, int]:
    t1 = t2 = 0
    for entry in authors:
        colon_pos = entry.rfind(":")
        if colon_pos != -1:
            tier_str = entry[colon_pos + 1:]
            if tier_str.isdigit():
                tier = int(tier_str)
                if tier == 1:
                    t1 += 1
                elif tier == 2:
                    t2 += 1
    return t1, t2


class IncidentGrouper:
    """신호 → 기존 Incident 매칭 또는 새 Incident 생성"""

    def __init__(self, client: Client):
        self.client = client
        self.table = "lumos_incident_groups"

    def match_or_create(self, signal: HackSignal) -> str | None:
        """
        신호를 기존 Incident에 매칭하거나, 새 그룹 생성.
        Returns: incident_group_id (UUID str) or None (매칭 실패)
        """
        # 규칙 1: tx_hash 매칭
        if signal.tx_hash:
            group = self._find_by_tx_hash(signal.tx_hash)
            if group:
                self._update_group(group["id"], signal)
                return group["id"]

        # 규칙 2: protocol_name + 시간 윈도우
        if signal.protocol_name:
            group = self._find_by_protocol(
                signal.protocol_name, signal.published_at
            )
            if group:
                self._update_group(group["id"], signal)
                return group["id"]

        # 규칙 3: attacker_address + 시간 윈도우
        if signal.attacker_address:
            group = self._find_by_attacker(
                signal.attacker_address, signal.published_at
            )
            if group:
                self._update_group(group["id"], signal)
                return group["id"]

        # 매칭 없음 → 새 그룹 생성
        return self._create_group(signal)

    # ── 검색 메서드 ──

    def _find_by_tx_hash(self, tx_hash: str) -> dict[str, Any] | None:
        """tx_hash로 기존 그룹 검색"""
        try:
            result = (
                self.client.table(self.table)
                .select("*")
                .eq("tx_hash", tx_hash)
                .limit(1)
                .execute()
            )
            raw = result.data[0] if result.data else None
            return cast(dict[str, Any], raw) if isinstance(raw, dict) else None
        except Exception:
            return None

    def _find_by_protocol(
        self, protocol_name: str, published_at: datetime
    ) -> dict[str, Any] | None:
        """protocol_name + 시간 윈도우로 검색"""
        try:
            cutoff = (published_at - PROTOCOL_WINDOW).isoformat()
            result = (
                self.client.table(self.table)
                .select("*")
                .eq("protocol_name", protocol_name)
                .gte("first_seen_at", cutoff)
                .order("first_seen_at", desc=True)
                .limit(1)
                .execute()
            )
            raw = result.data[0] if result.data else None
            return cast(dict[str, Any], raw) if isinstance(raw, dict) else None
        except Exception:
            return None

    def _find_by_attacker(
        self, attacker_address: str, published_at: datetime
    ) -> dict[str, Any] | None:
        """attacker_address + 시간 윈도우로 검색"""
        try:
            cutoff = (published_at - ATTACKER_WINDOW).isoformat()
            result = (
                self.client.table(self.table)
                .select("*")
                .eq("attacker_address", attacker_address)
                .gte("first_seen_at", cutoff)
                .order("first_seen_at", desc=True)
                .limit(1)
                .execute()
            )
            raw = result.data[0] if result.data else None
            return cast(dict[str, Any], raw) if isinstance(raw, dict) else None
        except Exception:
            return None

    # ── 생성 / 업데이트 ──

    def _create_group(self, signal: HackSignal) -> str:
        """새 Incident 그룹 생성"""
        author_key = _author_key(signal)
        source_authors = [f"{author_key}:{signal.source_author_tier}"] if author_key else []
        t1, t2 = _tier_counts(source_authors)
        data = {
            "protocol_name": signal.protocol_name,
            "chain": signal.chain,
            "loss_usd": float(signal.loss_usd) if signal.loss_usd else None,
            "tx_hash": signal.tx_hash,
            "attacker_address": signal.attacker_address,
            "first_seen_at": signal.published_at.isoformat(),
            "signal_count": 1,
            "source_types": [signal.source.value],
            "source_authors": source_authors,
            "source_author_count": len(source_authors),
            "tier1_author_count": t1,
            "tier2_author_count": t2,
            "confidence_score": 0,
            "best_tier": signal.source_author_tier,
        }

        result = (
            self.client.table(self.table)
            .insert(data)
            .execute()
        )
        row = cast(dict[str, Any], result.data[0])
        return str(row["id"])

    def _update_group(self, group_id: str, signal: HackSignal):
        """기존 그룹에 새 신호 정보 병합"""
        # 현재 그룹 가져오기
        result = (
            self.client.table(self.table)
            .select("*")
            .eq("id", group_id)
            .limit(1)
            .execute()
        )
        if not result.data:
            return

        group: dict[str, Any] = cast(dict[str, Any], result.data[0])

        # source_types 업데이트 (중복 제거)
        raw_types = group.get("source_types")
        existing_types: list[str] = (
            [str(t) for t in raw_types if isinstance(t, str)]
            if isinstance(raw_types, list)
            else []
        )
        source_types = list(set(existing_types + [signal.source.value]))

        raw_authors = group.get("source_authors")
        existing_authors: list[str] = (
            [str(a) for a in raw_authors if isinstance(a, str)]
            if isinstance(raw_authors, list)
            else []
        )
        source_authors = _merge_authors(existing_authors, signal)
        t1, t2 = _tier_counts(source_authors)

        raw_count = group.get("signal_count")
        new_signal_count: int = int(raw_count) + 1 if isinstance(raw_count, (int, float)) else 1

        # 필드 보강 (없던 값이 새로 들어오면 업데이트)
        updates: dict[str, Any] = {
            "signal_count": new_signal_count,
            "source_types": source_types,
            "source_authors": source_authors,
            "source_author_count": len(source_authors),
            "tier1_author_count": t1,
            "tier2_author_count": t2,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

        # best_tier 갱신 (낮은 숫자 = 높은 신뢰도)
        raw_best = group.get("best_tier")
        current_best: int = int(raw_best) if isinstance(raw_best, (int, float)) else 3
        if signal.source_author_tier < current_best:
            updates["best_tier"] = signal.source_author_tier

        if signal.tx_hash and not group.get("tx_hash"):
            updates["tx_hash"] = signal.tx_hash
        if signal.loss_usd and not group.get("loss_usd"):
            updates["loss_usd"] = float(signal.loss_usd)
        if signal.protocol_name and not group.get("protocol_name"):
            updates["protocol_name"] = signal.protocol_name
        if signal.chain and not group.get("chain"):
            updates["chain"] = signal.chain
        if signal.attacker_address and not group.get("attacker_address"):
            updates["attacker_address"] = signal.attacker_address

        self.client.table(self.table).update(updates).eq("id", group_id).execute()
