"""HackSignal 데이터 모델 — 해킹 감지 신호의 정규화된 표현"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4


class SourceType(str, Enum):
    """신호의 출처 유형"""
    TWITTER = "twitter"
    TELEGRAM = "telegram"


@dataclass
class HackSignal:
    """
    하나의 SNS 게시글 = 하나의 "신호(signal)".
    완성된 인시던트가 아니라 raw data + 메타데이터.

    - raw_text: 순수 텍스트 원문 (가장 중요, 변환 없이 그대로)
    - 나머지 필수 필드: 소스 메타데이터 (어디서, 언제, 누가)
    - optional 필드: Field Extractor가 채움 (Phase 0.1.5)
    """

    # === 필수: 원문 + 소스 메타데이터 ===
    raw_text: str                              # 순수 텍스트 원문 (가장 중요!)
    source: SourceType                         # twitter | telegram
    source_id: str                             # 원본 고유 ID (tg_chatid_msgid)
    source_url: str                            # 원본 URL
    source_author: str                         # 채널명 / 계정명
    source_author_tier: int                    # 신뢰도 Tier (1/2/3)
    published_at: datetime                     # 원본 게시 시각

    # === Phase 0.1.5에서 채움 (Field Extractor) ===
    protocol_name: str | None = None
    chain: str | None = None
    loss_usd: float | None = None
    tx_hash: str | None = None
    attacker_address: str | None = None

    # === 자동 생성 ===
    id: str = field(default_factory=lambda: str(uuid4()))
    crawled_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    media_urls: list[str] = field(default_factory=list)

    # === Incident Grouper가 할당 (Phase 0.2.5) ===
    incident_group_id: str | None = None

    @classmethod
    def from_telegram(
        cls,
        message,
        channel_name: str,
        channel_tier: int,
        chat_id: int,
    ) -> "HackSignal":
        """
        텔레그램 메시지 → HackSignal 변환.

        raw_text는 그대로 보존하고,
        나머지 메타데이터(URL, 게시자, 시각)만 정리.
        텍스트 내용 분석(protocol, tx_hash 등)은 여기서 하지 않음.
        """
        # source_url: https://t.me/c/{channel_id}/{message_id}
        channel_id_str = str(abs(chat_id))
        if channel_id_str.startswith("100"):
            channel_id_str = channel_id_str[3:]
        source_url = f"https://t.me/c/{channel_id_str}/{message.id}"

        # media URLs 수집
        media_urls: list[str] = []
        if message.photo:
            media_urls.append(f"photo:{message.id}")
        if message.document:
            media_urls.append(f"doc:{message.id}")

        return cls(
            raw_text=message.text or "",
            source=SourceType.TELEGRAM,
            source_id=f"tg_{chat_id}_{message.id}",
            source_url=source_url,
            source_author=channel_name,
            source_author_tier=channel_tier,
            published_at=message.date,
            media_urls=media_urls,
        )

    @classmethod
    def from_tweet(cls, tweet, tier: int = 2) -> "HackSignal":
        """
        twscrape Tweet 객체 → HackSignal 변환.

        tweet attrs: .id, .rawContent, .user.username, .date
        텍스트 내용 분석(protocol, tx_hash 등)은 여기서 하지 않음
        — field_extractor가 채움.
        """
        from src.extractors.field_extractor import extract_all

        fields = extract_all(tweet.rawContent)
        return cls(
            raw_text=tweet.rawContent,
            source=SourceType.TWITTER,
            source_id=f"tw:{tweet.id}",
            source_url=f"https://x.com/{tweet.user.username}/status/{tweet.id}",
            source_author=tweet.user.username,
            source_author_tier=tier,
            published_at=tweet.date,
            protocol_name=fields["protocol_name"],
            chain=fields["chain"],
            loss_usd=fields["loss_usd"],
            tx_hash=fields["tx_hash"],
            attacker_address=fields["attacker_address"],
        )

