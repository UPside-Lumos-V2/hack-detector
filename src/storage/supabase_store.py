"""Supabase 기반 HackSignal 저장소"""
import json

from supabase import Client

from src.models import HackSignal
from src.config import get_supabase_client
from src.normalizer import has_hack_keyword


class SignalStore:
    """lumos_hack_signals + lumos_skipped_messages 테이블 관리"""

    def __init__(self):
        self.client: Client = get_supabase_client()

    def insert(self, signal: HackSignal) -> bool:
        """
        HackSignal 저장.
        UNIQUE(source, source_id) 위반 시 False 반환.
        Postgres error code 23505 (unique_violation)으로 판별.
        """
        data = {
            "raw_text": signal.raw_text,
            "source": signal.source.value,
            "source_id": signal.source_id,
            "source_url": signal.source_url,
            "source_author": signal.source_author,
            "source_author_tier": signal.source_author_tier,
            "published_at": signal.published_at.isoformat(),
            "crawled_at": signal.crawled_at.isoformat(),
            "protocol_name": signal.protocol_name,
            "chain": signal.chain,
            "loss_usd": float(signal.loss_usd) if signal.loss_usd else None,
            "tx_hash": signal.tx_hash,
            "attacker_address": signal.attacker_address,
            "media_urls": signal.media_urls,
            "has_hack_keyword": has_hack_keyword(signal.raw_text),
        }

        try:
            self.client.table("lumos_hack_signals").insert(data).execute()
            return True
        except Exception as e:
            error_str = str(e)
            # Postgres unique_violation (23505)
            if "23505" in error_str or "duplicate" in error_str.lower():
                return False
            raise

    def log_skip(
        self,
        reason: str,
        source: str,
        channel_name: str,
        channel_id: int,
        message_id: int,
        raw_text: str,
    ):
        """skip된 메시지를 lumos_skipped_messages에 저장"""
        try:
            self.client.table("lumos_skipped_messages").insert({
                "skip_reason": reason,
                "source": source,
                "channel_name": channel_name,
                "channel_id": channel_id,
                "message_id": message_id,
                "raw_text": raw_text,
            }).execute()
        except Exception as e:
            # skip 로깅 실패는 치명적이지 않음 — 파일 로그로 대체
            print(f"  ⚠️ skip 로깅 실패: {e}")

    def count(self) -> int:
        """전체 hack_signals 수"""
        result = self.client.table("lumos_hack_signals") \
            .select("id", count="exact").execute()
        return result.count or 0
