"""Telethon MTProto 리스너 — 공개 채널 실시간 모니터링"""
from telethon import TelegramClient
from src.config import SESSION_PATH, get_credentials


async def create_client() -> TelegramClient:
    """
    Telethon 클라이언트 생성 + 로그인.

    첫 실행 시 전화번호 + 인증코드 입력 필요 (1회성).
    이후에는 세션 파일(sessions/hack_detector.session)로 자동 로그인.

    기존 kakaobot(user_session)과는 세션 파일이 분리되어 충돌 없음.
    """
    api_id, api_hash = get_credentials()

    client = TelegramClient(SESSION_PATH, api_id, api_hash)
    await client.start()  # 첫 실행: 전화번호+인증코드 프롬프트 자동 표시

    me = await client.get_me()
    print(f"✅ Logged in as: {me.first_name} ({me.phone})")
    print(f"📁 Session: {SESSION_PATH}.session")

    return client


async def test_channel_read(
    client: TelegramClient, channel: str, limit: int = 5
) -> list:
    """
    테스트: 단일 공개 채널에서 최근 메시지 N개 읽기.
    채널에 가입되어 있지 않아도 공개 채널이면 읽기 가능.
    """
    try:
        entity = await client.get_entity(channel)
        title = getattr(entity, "title", channel)
        username = getattr(entity, "username", "?")
        print(f"\n📡 Channel: {title} (@{username})")
        print("=" * 50)

        messages = []
        async for message in client.iter_messages(entity, limit=limit):
            if message.text:
                preview = message.text[:120].replace("\n", " ")
                print(
                    f"  [{message.date.strftime('%m/%d %H:%M')}] {preview}"
                )
                messages.append(message)

        print(f"  → {len(messages)}개 메시지 수신 성공\n")
        return messages

    except Exception as e:
        print(f"  ⚠️ {channel} 읽기 실패: {e}\n")
        return []
