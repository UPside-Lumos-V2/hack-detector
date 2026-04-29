"""Supabase 기반 HackSignal 저장소"""
import asyncio
import json
import time
from datetime import datetime, timezone

from supabase import Client

from src.models import HackSignal
from src.config import get_supabase_client
from src.normalizer import has_hack_keyword
from src.grouper import IncidentGrouper
from src.scorer import calculate_confidence
from src.alerter import AlertRuleEngine
from src.deduplicator import AlertDeduplicator
from src.formatter import AlertFormatter
from src.notifier import send_alert
from src.logger import StructuredLogger

logger = StructuredLogger("store")


class SignalStore:
    """lumos_hack_signals + lumos_skipped_messages + lumos_incident_groups 관리"""

    def __init__(self):
        self.client: Client = get_supabase_client()
        self.grouper = IncidentGrouper(self.client)
        self.alert_engine = AlertRuleEngine()
        self.deduplicator = AlertDeduplicator(self.client)
        self.formatter = AlertFormatter()

    def insert(self, signal: HackSignal) -> bool:
        """
        HackSignal 저장 + Incident 그룹핑 + Confidence 점수 산출.
        UNIQUE(source, source_id) 위반 시 False 반환.
        """
        # 1. Incident 그룹 매칭/생성
        group_id = None
        confidence = 0
        group_data = None
        grp = None  # 최종 그룹 상태 (confidence 반영 후)
        try:
            group_id = self.grouper.match_or_create(signal)
            if group_id:
                # 그룹 데이터 가져와서 점수 계산
                group_data = (
                    self.client.table("lumos_incident_groups")
                    .select("*")
                    .eq("id", group_id)
                    .limit(1)
                    .execute()
                )
                if group_data.data:
                    confidence = calculate_confidence(group_data.data[0])
                    # 그룹 confidence 업데이트
                    self.client.table("lumos_incident_groups").update(
                        {"confidence_score": confidence}
                    ).eq("id", group_id).execute()
                    # Critical 2: 업데이트된 confidence를 반영한 최종 그룹 상태
                    grp = {**group_data.data[0], "confidence_score": confidence}
        except Exception as e:
            # 그룹핑 실패해도 신호 저장은 계속
            logger.error("grouper", "match_or_create", str(e), recoverable=True)

        # 2. Alert 판정 (signal 저장 후 실행하기 위해 결과만 미리 계산)
        alert_status = "pending"
        alert_decision_data = None  # (action, grp, new_fields) 저장용
        if group_id and grp:
            try:
                decision = self.alert_engine.evaluate(grp)
                if decision.should_alert:
                    dedup_result = self.deduplicator.check(group_id, grp)
                    if dedup_result.action == "first_alert":
                        alert_status = "alerted"
                        alert_decision_data = ("first_alert", grp, [])
                    elif dedup_result.action == "follow_up":
                        alert_status = "follow_up"
                        # Critical 4: deduplicator가 반환한 실제 새 필드만 사용
                        alert_decision_data = ("follow_up", grp, dedup_result.new_fields)
                    else:
                        alert_status = "silent"
                else:
                    alert_status = "silent"
            except Exception as e:
                logger.error("alerter", "evaluate", str(e), recoverable=True)

        # 3. 신호 저장
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
            "incident_group_id": group_id,
            "confidence_score": confidence,
            "alert_status": alert_status,
            # Gemini LLM 분류 결과
            "llm_is_hack": signal.llm_is_hack,
            "llm_confidence": signal.llm_confidence,
            "llm_category": signal.llm_category,
            "llm_summary": signal.llm_summary,
        }

        try:
            result = self.client.table("lumos_hack_signals").insert(data).execute()
            # 저장된 signal의 DB id 추출
            stored_signal_id = result.data[0]["id"] if result.data else None

            # 4. Alert 레코드 저장 (signal이 DB에 존재한 후)
            if alert_decision_data and stored_signal_id:
                action_type, alert_grp, new_fields = alert_decision_data
                if action_type == "first_alert":
                    alert_msg = self.formatter.format_first_alert(group_id, alert_grp, source_url=signal.source_url)
                    alert_id = self._insert_alert(alert_msg, stored_signal_id)
                    logger.alert_fired(group_id, "critical", "first_alert", alert_msg.title)
                    # Telegram 발송
                    self._schedule_telegram(alert_msg.body, alert_id)
                elif action_type == "follow_up":
                    alert_msg = self.formatter.format_follow_up(group_id, alert_grp, new_fields, source_url=signal.source_url)
                    alert_id = self._insert_alert(alert_msg, stored_signal_id)
                    logger.alert_fired(group_id, "follow_up", "follow_up", alert_msg.title)
                    # Telegram 발송
                    self._schedule_telegram(alert_msg.body, alert_id)

            # 신호 저장 로그
            logger.signal_stored(
                source=signal.source.value,
                author=signal.source_author,
                protocol=signal.protocol_name,
                alert_status=alert_status,
                confidence=confidence,
            )

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
            # skip 로깅 실패는 치명적이지 않음
            logger.error("store", "log_skip", str(e), recoverable=True)

    def count(self) -> int:
        """전체 hack_signals 수"""
        result = self.client.table("lumos_hack_signals") \
            .select("id", count="exact").execute()
        return result.count or 0

    def _insert_alert(self, alert_msg, trigger_signal_id: str) -> str | None:
        """lumos_hack_alerts에 알림 레코드 저장. 실패 시 1회 재시도. alert ID 반환."""
        data = {
            "incident_group_id": alert_msg.incident_group_id,
            "alert_level": alert_msg.alert_level,
            "alert_action": alert_msg.alert_action,
            "title": alert_msg.title,
            "body": alert_msg.body,
            "source_count": alert_msg.source_count,
            "metadata": alert_msg.metadata,
            "trigger_signal_id": trigger_signal_id,
        }
        try:
            result = self.client.table("lumos_hack_alerts").insert(data).execute()
            return result.data[0]["id"] if result.data else None
        except Exception as e:
            # 1회 재시도
            logger.error("store", "insert_alert", f"retry: {e}", recoverable=True)
            try:
                time.sleep(0.5)
                result = self.client.table("lumos_hack_alerts").insert(data).execute()
                return result.data[0]["id"] if result.data else None
            except Exception as e2:
                logger.error("store", "insert_alert", f"final fail: {e2}", recoverable=False)
                return None

    def _schedule_telegram(self, body: str, alert_id: str | None) -> None:
        """Telegram 발송을 비동기로 스케줄링."""
        async def _do_send():
            try:
                sent = await send_alert(body)
                if sent and alert_id:
                    self.client.table("lumos_hack_alerts").update({
                        "sent_at": datetime.now(timezone.utc).isoformat(),
                        "sent_to": "telegram",
                    }).eq("id", alert_id).execute()
            except Exception as e:
                logger.error("store", "telegram_send", str(e), recoverable=True)

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.ensure_future(_do_send())
            else:
                loop.run_until_complete(_do_send())
        except RuntimeError:
            # 이벤트 루프가 없는 경우 (테스트 등)
            asyncio.run(_do_send())
