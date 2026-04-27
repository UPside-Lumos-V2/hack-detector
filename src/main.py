"""Hack Detector — 엔트리포인트"""
import asyncio
import sys

from src.config import load_channels, load_twitter_accounts, get_twitter_poll_interval
from src.listeners.telegram import create_client, test_channel_read, start_listening
from src.listeners.twitter import TwitterPoller
from src.storage.supabase_store import SignalStore
from src.logger import StructuredLogger

logger = StructuredLogger()


async def main() -> None:
    mode = sys.argv[1] if len(sys.argv) > 1 else "test"

    # 1. 채널 목록 로딩
    channels = load_channels()
    if not channels:
        logger.error("config", "load_channels", "No channels in channels.yaml", recoverable=False)
        return

    # 2. Twitter 계정 로딩
    twitter_accounts = load_twitter_accounts()
    n_twitter = sum(len(v) for v in twitter_accounts.values()) if twitter_accounts else 0

    logger.startup(mode=mode, channels=len(channels), twitter_accounts=n_twitter)

    # 3. 클라이언트 연결
    client = await create_client()

    if mode == "test":
        # 테스트 모드: 각 채널의 최근 메시지 읽기
        logger.info({"event": "test_mode", "channels": len(channels)})
        for channel in channels:
            await test_channel_read(client, channel)
        logger.info({"event": "test_complete"})
        await client.disconnect()

    elif mode == "listen":
        # 리스닝 모드: Telegram 실시간 + Twitter 폴링 동시 실행
        logger.info({"event": "listen_mode"})

        # Twitter 폴러를 별도 태스크로 실행
        if twitter_accounts:
            store = SignalStore()
            interval = get_twitter_poll_interval()
            poller = TwitterPoller(store, twitter_accounts)
            asyncio.create_task(poller.start(interval=interval))

        await start_listening(client, channels)

    else:
        logger.error("main", "parse_mode", f"Unknown mode: {mode}", recoverable=False)
        print(f"Usage: python -m src.main [test|listen]")
        await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
