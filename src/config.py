"""
설정 관리 — API 크레덴셜은 .env가 아닌 터미널 직접 입력.
기존 kakaobot과 동일한 api_id/hash 재사용 가능.
세션 파일명을 'hack_detector'로 분리하여 충돌 방지.
"""
import os
from pathlib import Path


# ── 경로 ──
PROJECT_ROOT = Path(__file__).parent.parent
SESSIONS_DIR = PROJECT_ROOT / "sessions"
SESSIONS_DIR.mkdir(exist_ok=True)

# kakaobot의 "user_session"과 반드시 다른 이름
SESSION_NAME = "hack_detector"
SESSION_PATH = str(SESSIONS_DIR / SESSION_NAME)


def get_credentials() -> tuple[int, str]:
    """
    API 크레덴셜을 가져온다.
    우선순위: 환경변수 → 터미널 직접 입력
    .env 파일에 저장하지 않음 (기록 안 남김).
    
    기존 kakaobot과 동일한 api_id/hash 사용 가능.
    """
    api_id_raw = os.getenv("API_ID") or input("Telegram API ID: ")
    api_hash = os.getenv("API_HASH") or input("Telegram API Hash: ")

    return int(api_id_raw), api_hash
