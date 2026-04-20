"""Telethon MTProto 리스너 — 공개 채널 실시간 모니터링"""
from telethon import TelegramClient, events
from src.config import SESSION_PATH, ChannelConfig, get_credentials, load_channels
from src.normalizer import process_message
from src.storage.supabase_store import SignalStore


async def create_client() -> TelegramClient:
    """
    Telethon 클라이언트 생성 + 로그인.
    첫 실행 시 전화번호 + 인증코드 입력 필요 (1회성).
    이후에는 세션 파일로 자동 로그인.
    """
    api_id, api_hash = get_credentials()

    client = TelegramClient(SESSION_PATH, api_id, api_hash)
    await client.start()

    me = await client.get_me()
    print(f"✅ Logged in as: {me.first_name} ({me.phone})")
    print(f"📁 Session: {SESSION_PATH}.session")

    return client


async def test_channel_read(
    client: TelegramClient, channel: ChannelConfig, limit: int = 5
) -> list:
    """테스트: 단일 채널에서 최근 메시지 N개 읽기 (chat_id 기반)"""
    try:
        entity = await client.get_entity(channel.chat_id)
        title = getattr(entity, "title", channel.name)
        print(f"\n📡 Channel: {title} (ID: {channel.chat_id}, Tier {channel.tier})")
        print("=" * 60)

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
        print(f"  ⚠️ {channel.name} (ID: {channel.chat_id}) 읽기 실패: {e}\n")
        return []


async def start_listening(client: TelegramClient, channels: list[ChannelConfig]):
    """
    실시간 이벤트 리스닝 — 채널에 새 메시지가 올라오면 콜백 호출.
    폴링 불필요, WebSocket 류 실시간 수신.
    """
    # Supabase 저장소 초기화
    store = SignalStore()
    print(f"💾 Supabase 연결 완료")

    chat_ids = [ch.chat_id for ch in channels]
    channel_map = {ch.chat_id: ch for ch in channels}

    @client.on(events.NewMessage(chats=chat_ids))
    async def on_new_message(event):
        message = event.message
        chat_id = event.chat_id
        ch = channel_map.get(chat_id)
        if not ch:
            return

        # Normalizer: 필터링 → 필드 추출 → HackSignal
        signal = process_message(message, ch, store=store)
        if signal is None:
            return  # skip (skipped.log + Supabase에 기록됨)

        # Supabase에 저장
        inserted = store.insert(signal)
        if not inserted:
            return  # 중복 — 이미 저장됨

        # 감지 출력
        print(f"\n🔔 [{signal.source_author}] (Tier {signal.source_author_tier})")
        print(f"   📝 {signal.raw_text[:200]}")
        if signal.protocol_name:
            print(f"   🏷️  Protocol: {signal.protocol_name}")
        if signal.chain:
            print(f"   ⛓️  Chain: {signal.chain}")
        if signal.loss_usd:
            print(f"   💰 Loss: ${signal.loss_usd:,.0f}")
        if signal.tx_hash:
            print(f"   🔗 Tx: {signal.tx_hash[:20]}...")
        if signal.attacker_address:
            print(f"   👤 Attacker: {signal.attacker_address}")
        print(f"   📅 {signal.published_at}")
        print(f"   🆔 {signal.id}")
        print(f"   💾 Supabase 저장 (총 {store.count()}건)")

    print(f"\n👂 {len(channels)}개 채널 실시간 리스닝 시작...")
    for ch in channels:
        print(f"   • {ch.name} (ID: {ch.chat_id}, Tier {ch.tier})")
    print("\n💡 Ctrl+C로 종료\n")

    await client.run_until_disconnected()
