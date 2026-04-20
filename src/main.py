"""Hack Detector — 엔트리포인트"""
import asyncio

from src.listeners.telegram import create_client, test_channel_read


async def main() -> None:
    print("🔍 Hack Detector — Telethon 연결 테스트")
    print("=" * 50)

    # 1. 클라이언트 연결 (API 크레덴셜 터미널 입력)
    client = await create_client()

    # 2. 테스트: 보안 채널 메시지 읽기
    test_channels = [
        "PeckShieldAlert",
    ]

    for channel in test_channels:
        await test_channel_read(client, channel)

    print("🎉 T0.1.2 완료 — Telethon 연결 성공!")
    print("💡 세션 파일이 저장되었으므로 다음 실행부터는 자동 로그인됩니다.")

    await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
