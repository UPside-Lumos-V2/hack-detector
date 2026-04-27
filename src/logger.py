"""StructuredLogger — JSON-line 구조화 로깅

모든 print() 대체용. stdout에 JSON-line으로 출력.
GCP Logging / CloudWatch 등에서 바로 파싱 가능.
"""
import json
import logging
import sys
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    """logging.Formatter → JSON-line 출력"""

    def format(self, record: logging.LogRecord) -> str:
        payload = record.msg if isinstance(record.msg, dict) else {"message": str(record.msg)}
        log_entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            **payload,
        }
        return json.dumps(log_entry, ensure_ascii=False, default=str)


def get_logger(name: str = "hack-detector") -> logging.Logger:
    """싱글턴 로거 반환. 중복 핸들러 방지."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)

    # 상위 로거 전파 차단 (중복 출력 방지)
    logger.propagate = False

    return logger


class StructuredLogger:
    """비즈니스 로직용 구조화 로거"""

    def __init__(self, name: str = "hack-detector"):
        self._log = get_logger(name)

    # ── 신호 ──

    def signal_stored(
        self,
        source: str,
        author: str,
        protocol: str | None,
        alert_status: str,
        confidence: int,
    ):
        self._log.info({
            "event": "signal_stored",
            "source": source,
            "author": author,
            "protocol": protocol,
            "alert_status": alert_status,
            "confidence": confidence,
        })

    def signal_skipped(self, source: str, author: str, reason: str):
        self._log.debug({
            "event": "signal_skipped",
            "source": source,
            "author": author,
            "reason": reason,
        })

    # ── 알림 ──

    def alert_fired(
        self,
        group_id: str,
        level: str,
        action: str,
        title: str,
    ):
        self._log.warning({
            "event": "alert_fired",
            "group_id": group_id,
            "level": level,
            "action": action,
            "title": title,
        })

    # ── 에러 ──

    def error(
        self,
        component: str,
        action: str,
        msg: str,
        recoverable: bool = True,
    ):
        self._log.error({
            "event": "error",
            "component": component,
            "action": action,
            "error": msg,
            "recoverable": recoverable,
        })

    # ── 사이클 통계 ──

    def cycle(
        self,
        signals_new: int,
        alerts_fired: int,
        skipped: int,
        errors: int,
        duration_ms: int,
    ):
        self._log.info({
            "event": "cycle_stats",
            "signals_new": signals_new,
            "alerts_fired": alerts_fired,
            "skipped": skipped,
            "errors": errors,
            "duration_ms": duration_ms,
        })

    # ── 시스템 ──

    def startup(self, mode: str, channels: int, twitter_accounts: int):
        self._log.info({
            "event": "startup",
            "mode": mode,
            "telegram_channels": channels,
            "twitter_accounts": twitter_accounts,
        })

    def info(self, msg: dict | str):
        if isinstance(msg, str):
            msg = {"message": msg}
        self._log.info(msg)
