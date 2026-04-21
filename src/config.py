"""
설정 관리 — API 크레덴셜은 .env에서 자동 로딩 (gitignore 됨, git에 안 올라감).
"""
import os
from pathlib import Path
from dataclasses import dataclass

import yaml
from dotenv import load_dotenv

# .env 파일이 있으면 자동 로딩 (없으면 무시)
load_dotenv()


# ── 경로 ──
PROJECT_ROOT = Path(__file__).parent.parent
SESSIONS_DIR = PROJECT_ROOT / "sessions"
SESSIONS_DIR.mkdir(exist_ok=True)
CONFIG_DIR = PROJECT_ROOT / "config"

# kakaobot의 "user_session"과 반드시 다른 이름
SESSION_NAME = "hack_detector"
SESSION_PATH = str(SESSIONS_DIR / SESSION_NAME)


@dataclass
class ChannelConfig:
    """모니터링 대상 채널 설정"""
    chat_id: int
    name: str
    tier: int  # 1=보안업체/전문, 2=커뮤니티, 3=기타


def get_credentials() -> tuple[int, str]:
    """
    API 크레덴셜을 .env에서 로딩.
    .env가 없으면 터미널 입력 폴백.
    .env는 .gitignore에 등록되어 있어 git에 안 올라감.
    """
    api_id_raw = os.getenv("API_ID") or input("Telegram API ID: ")
    api_hash = os.getenv("API_HASH") or input("Telegram API Hash: ")

    return int(api_id_raw), api_hash


def load_channels() -> list[ChannelConfig]:
    """channels.yaml에서 모니터링 채널 목록 로딩"""
    channels_file = CONFIG_DIR / "channels.yaml"

    if not channels_file.exists():
        print(f"⚠️ 채널 설정 파일 없음: {channels_file}")
        return []

    with open(channels_file, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    channels = []
    for ch in data.get("channels", []):
        channels.append(ChannelConfig(
            chat_id=ch["chat_id"],
            name=ch["name"],
            tier=ch.get("tier", 3),
        ))

    return channels


def get_supabase_client():
    """
    Supabase 클라이언트 (service_role 키).
    hack-detector 전용 — INSERT 권한 필요 (RLS bypass).
    Workflow와 동일 인스턴스, 다른 키.
    """
    from supabase import create_client

    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_KEY")
    if not url or not key:
        raise RuntimeError(
            "SUPABASE_URL, SUPABASE_SERVICE_KEY 필요 (.env 확인)"
        )
    return create_client(url, key)


def load_twitter_accounts() -> dict[str, list[dict]] | None:
    """
    config/accounts.yaml에서 Twitter 모니터링 대상 계정 로딩.
    없으면 None 반환 (Twitter 폴링 비활성).
    """
    accounts_file = CONFIG_DIR / "accounts.yaml"
    if not accounts_file.exists():
        print("⚠️ config/accounts.yaml 없음 — Twitter 폴링 비활성")
        return None

    with open(accounts_file, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    accounts = data.get("twitter_accounts")
    if not accounts:
        return None

    return accounts


def get_twitter_poll_interval() -> int:
    """accounts.yaml에서 폴링 간격 로딩 (기본 300초)"""
    accounts_file = CONFIG_DIR / "accounts.yaml"
    if not accounts_file.exists():
        return 300

    with open(accounts_file, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    return data.get("poll_interval_seconds", 300)


def get_xai_client():
    """
    xAI Grok API 클라이언트 (OpenAI 호환) — 폴백용.
    XAI_API_KEY가 없으면 RuntimeError 발생 → 폴백 비활성.
    """
    from openai import OpenAI

    api_key = os.getenv("XAI_API_KEY")
    if not api_key:
        raise RuntimeError("XAI_API_KEY 미설정 — xAI 폴백 비활성")
    return OpenAI(api_key=api_key, base_url="https://api.x.ai/v1")

