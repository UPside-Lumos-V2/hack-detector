"""Hack Detector — 엔트리포인트"""
import asyncio
import sys

from src.config import load_channels
from src.listeners.telegram import create_client, test_channel_read, start_listening


async def main() -> None:
    mode = sys.argv[1] if len(sys.argv) > 1 else "test"

    print("🔍 Hack Detector")
    print("=" * 60)

    # 1. 채널 목록 로딩
    channels = load_channels()
    if not channels:
        print("❌ 모니터링 채널이 없습니다. config/channels.yaml을 확인하세요.")
        return

    print(f"📋 {len(channels)}개 채널 로딩 완료")

    # 2. 클라이언트 연결
    client = await create_client()

    if mode == "test":
        # 테스트 모드: 각 채널의 최근 메시지 읽기
        print("\n📖 테스트 모드 — 각 채널 최근 메시지 확인\n")
        for channel in channels:
            await test_channel_read(client, channel)
        print("🎉 테스트 완료!")
        await client.disconnect()

    elif mode == "listen":
        # 리스닝 모드: 실시간 새 메시지 감지
        print("\n🎧 리스닝 모드 — 실시간 감지 시작\n")
        await start_listening(client, channels)

    else:
        print(f"❌ 알 수 없는 모드: {mode}")
        print("사용법: python -m src.main [test|listen]")
        await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
