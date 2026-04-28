"""Twitter/X Poller — httpx 직접 GraphQL + xAI 폴백

twscrape/twikit는 x-client-transaction-id 파싱 이슈로 사용 불가.
httpx + 쿠키로 직접 GraphQL API 호출 (x-client-transaction-id 불필요).

세션 관리: cookies.json (auth_token + ct0)
서버 배포: scp cookies.json 로 이관.
"""
import asyncio
import json
import logging
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path

import httpx

from src.models import HackSignal, SourceType
from src.normalizer import should_skip
from src.extractors.field_extractor import extract_all
from src.storage.supabase_store import SignalStore
from src.config import PROJECT_ROOT


logger = logging.getLogger(__name__)

# ── Gemini 분류기 (싱글톤) ──
_classifier = None


def _get_classifier():
    """GeminiClassifier 싱글톤 — Twitter 파이프라인용."""
    global _classifier
    if _classifier is None:
        from src.classifiers.gemini_classifier import GeminiClassifier
        _classifier = GeminiClassifier()
    return _classifier

# Twitter 공개 bearer 토큰 (모든 클라이언트 동일, 변경 거의 없음)
BEARER = (
    "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs"
    "%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
)

COOKIES_PATH = PROJECT_ROOT / "cookies.json"

# GraphQL 공통 features
_USER_FEATURES = {
    "hidden_profile_subscriptions_enabled": True,
    "rweb_tipjar_consumption_enabled": True,
    "responsive_web_graphql_exclude_directive_enabled": True,
    "verified_phone_label_enabled": False,
    "subscriptions_verification_info_is_identity_verified_enabled": True,
    "responsive_web_graphql_skip_user_profile_image_extensions_enabled": False,
    "responsive_web_graphql_timeline_navigation_enabled": True,
}

_TWEET_FEATURES = {
    "rweb_tipjar_consumption_enabled": True,
    "responsive_web_graphql_exclude_directive_enabled": True,
    "verified_phone_label_enabled": False,
    "creator_subscriptions_tweet_preview_api_enabled": True,
    "responsive_web_graphql_timeline_navigation_enabled": True,
    "responsive_web_graphql_skip_user_profile_image_extensions_enabled": False,
    "communities_web_enable_tweet_community_results_fetch": True,
    "c9s_tweet_anatomy_moderator_badge_enabled": True,
    "articles_preview_enabled": True,
    "responsive_web_edit_tweet_api_enabled": True,
    "graphql_is_translatable_rweb_tweet_is_translatable_enabled": True,
    "view_counts_everywhere_api_enabled": True,
    "longform_notetweets_consumption_enabled": True,
    "responsive_web_twitter_article_tweet_consumption_enabled": True,
    "tweet_awards_web_tipping_enabled": False,
    "creator_subscriptions_quote_tweet_preview_enabled": False,
    "freedom_of_speech_not_reach_fetch_enabled": True,
    "standardized_nudges_misinfo": True,
    "tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled": True,
    "rweb_video_timestamps_enabled": True,
    "longform_notetweets_rich_text_read_enabled": True,
    "longform_notetweets_inline_media_enabled": True,
    "responsive_web_enhance_cards_enabled": False,
}


def load_cookies() -> dict[str, str]:
    """cookies.json에서 로드. 없으면 RuntimeError."""
    if not COOKIES_PATH.exists():
        raise RuntimeError(
            f"cookies.json 없음 → python scripts/setup_twitter.py 실행"
        )
    with open(COOKIES_PATH) as f:
        return json.load(f)


@dataclass
class RawTweet:
    """GraphQL 응답에서 추출한 트윗 데이터"""
    id: int
    text: str
    username: str
    created_at: datetime


def _expand_urls(text: str, entities: dict) -> str:
    """t.co 단축 URL을 실제 URL로 치환."""
    urls = entities.get("urls", [])
    for url_entity in urls:
        short = url_entity.get("url", "")
        expanded = url_entity.get("expanded_url", "")
        if short and expanded:
            text = text.replace(short, expanded)
    return text


def _parse_tweets(data: dict) -> list[RawTweet]:
    """UserTweets GraphQL 응답 → RawTweet 리스트"""
    tweets: list[RawTweet] = []
    try:
        instructions = (
            data["data"]["user"]["result"]["timeline_v2"]
            ["timeline"]["instructions"]
        )
    except (KeyError, TypeError):
        return tweets

    for instr in instructions:
        if instr.get("type") != "TimelineAddEntries":
            continue
        for entry in instr.get("entries", []):
            content = entry.get("content", {})
            result = (
                content.get("itemContent", {})
                .get("tweet_results", {})
                .get("result", {})
            )
            if not result or result.get("__typename") == "TweetTombstone":
                continue

            legacy = result.get("legacy", {})
            core = result.get("core", {}).get("user_results", {}).get("result", {})
            user_legacy = core.get("legacy", {})

            full_text = legacy.get("full_text", "")
            tweet_id_str = legacy.get("id_str", "")
            username = user_legacy.get("screen_name", "unknown")
            created_str = legacy.get("created_at", "")

            if not tweet_id_str or not full_text:
                continue

            # t.co → 실제 URL 확장
            entities = legacy.get("entities", {})
            full_text = _expand_urls(full_text, entities)

            try:
                dt = datetime.strptime(
                    created_str, "%a %b %d %H:%M:%S %z %Y"
                )
            except (ValueError, TypeError):
                dt = datetime.now(timezone.utc)

            tweets.append(RawTweet(
                id=int(tweet_id_str),
                text=full_text,
                username=username,
                created_at=dt,
            ))

    return tweets


class TwitterPoller:
    """httpx 직접 GraphQL 호출 기반 Twitter 폴러"""

    CACHE_PATH = PROJECT_ROOT / "last_ids.json"

    def __init__(self, store: SignalStore, accounts: dict[str, list[dict]]):
        self.store = store
        self.accounts = accounts
        self.cookies = load_cookies()

        # handle → (user_id, last_tweet_id)
        self._cache: dict[str, tuple[str, int]] = self._load_cache()
        self.consecutive_failures = 0
        self.using_fallback = False

    def _load_cache(self) -> dict[str, tuple[str, int]]:
        """last_ids.json에서 캐시 복원. 재시작해도 초기화 안 함."""
        if not self.CACHE_PATH.exists():
            return {}
        try:
            with open(self.CACHE_PATH) as f:
                raw = json.load(f)
            cache = {k: (v[0], v[1]) for k, v in raw.items()}
            print(f"  📂 last_ids.json에서 {len(cache)}개 계정 캐시 복원")
            return cache
        except (json.JSONDecodeError, KeyError, TypeError):
            return {}

    def _save_cache(self):
        """현재 캐시를 last_ids.json에 저장."""
        raw = {k: [v[0], v[1]] for k, v in self._cache.items()}
        with open(self.CACHE_PATH, "w") as f:
            json.dump(raw, f, indent=2)

    def _make_headers(self) -> dict[str, str]:
        return {
            "authorization": f"Bearer {BEARER}",
            "x-csrf-token": self.cookies["ct0"],
            "user-agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36"
            ),
            "content-type": "application/json",
        }

    def _make_cookies(self) -> dict[str, str]:
        return {
            "auth_token": self.cookies["auth_token"],
            "ct0": self.cookies["ct0"],
        }

    # ── user_id 해석 ──

    async def _resolve_user_id(
        self, client: httpx.AsyncClient, handle: str
    ) -> str:
        cached = self._cache.get(handle)
        if cached and cached[0]:
            return cached[0]

        variables = json.dumps({
            "screen_name": handle,
            "withSafetyModeUserFields": True,
        })
        rep = await client.get(
            "https://x.com/i/api/graphql/Yka-W8dz7RaEuQNkroPkYw/UserByScreenName",
            params={
                "variables": variables,
                "features": json.dumps(_USER_FEATURES),
            },
        )
        rep.raise_for_status()
        user_id = rep.json()["data"]["user"]["result"]["rest_id"]
        self._cache[handle] = (user_id, 0)
        self._save_cache()
        return user_id

    def _get_last_id(self, handle: str) -> int:
        return self._cache.get(handle, ("", 0))[1]

    def _set_last_id(self, handle: str, tweet_id: int):
        uid = self._cache.get(handle, ("", 0))[0]
        self._cache[handle] = (uid, tweet_id)
        self._save_cache()

    # ── 단일 계정 폴링 ──

    async def poll_account(
        self, client: httpx.AsyncClient, handle: str, tier: int
    ) -> int:
        try:
            user_id = await self._resolve_user_id(client, handle)
            last_id = self._get_last_id(handle)

            variables = json.dumps({
                "userId": user_id,
                "count": 20,
                "includePromotedContent": False,
                "withQuickPromoteEligibilityTweetFields": False,
                "withVoice": False,
                "withV2Timeline": True,
            })
            rep = await client.get(
                "https://x.com/i/api/graphql/E3opETHurmVJflFsUBVuUQ/UserTweets",
                params={
                    "variables": variables,
                    "features": json.dumps(_TWEET_FEATURES),
                },
            )
            # 429 rate limit = 이번 라운드 스킵
            if rep.status_code == 429:
                logger.warning(f"429 rate limit: @{handle}")
                return 0
            rep.raise_for_status()

            raw_tweets = _parse_tweets(rep.json())

            # 첫 폴링: last_id만 기록하고 실제 저장은 안 함 (기존 트윗 무시)
            if last_id == 0:
                if raw_tweets:
                    self._set_last_id(handle, max(t.id for t in raw_tweets))
                    print(f"   📌 @{handle} 초기화 (last_id={self._get_last_id(handle)})")
                return 0

            new_tweets = [t for t in raw_tweets if t.id > last_id]

            if new_tweets:
                self._set_last_id(handle, max(t.id for t in new_tweets))

            count = 0
            for tw in new_tweets:
                skip, reason = should_skip(tw.text)
                if skip:
                    self.store.log_skip(
                        reason=reason or "filtered",
                        source="twitter",
                        channel_name=handle,
                        channel_id=0,
                        message_id=tw.id,
                        raw_text=tw.text[:500],
                    )
                    continue

                fields = extract_all(tw.text)
                # 참조 트윗 URL resolve → raw_text에 append
                from src.extractors.tweet_resolver import (
                    resolve_tweet_urls,
                    append_resolved_to_text,
                )
                try:
                    resolved = await resolve_tweet_urls(tw.text)
                    enriched_text = append_resolved_to_text(tw.text, resolved)
                except Exception:
                    enriched_text = tw.text

                # resolve 후 재추출 (참조 트윗에서 추가 메타데이터)
                if enriched_text != tw.text:
                    fields = extract_all(enriched_text)

                # ── LLM 게이트: Gemini 분류 → is_hack 판정 ──
                from src.classifiers.gemini_classifier import (
                    GeminiClassifier,
                    merge_results,
                )
                classifier = _get_classifier()
                llm_result = None
                if classifier.available:
                    try:
                        llm_result = await classifier.classify(enriched_text)
                    except Exception as e:
                        print(f"  LLM classify error ({handle}): {e}")

                merged = merge_results(fields, llm_result)

                # LLM이 is_hack=false 판정 → skip
                if llm_result and not llm_result.is_hack:
                    self.store.log_skip(
                        reason=f"llm_not_hack({llm_result.category})",
                        source="twitter",
                        channel_name=handle,
                        channel_id=0,
                        message_id=tw.id,
                        raw_text=enriched_text[:500],
                    )
                    print(f"  ⏭️ [{handle}] LLM skip ({llm_result.category}): {tw.text[:60]}...")
                    continue

                # LLM이 is_hack=true이지만 과거 회고 → skip
                if llm_result and llm_result.is_hack and not llm_result.is_new_incident:
                    self.store.log_skip(
                        reason="llm_retrospective",
                        source="twitter",
                        channel_name=handle,
                        channel_id=0,
                        message_id=tw.id,
                        raw_text=enriched_text[:500],
                    )
                    print(f"  ⏭️ [{handle}] LLM retrospective: {tw.text[:60]}...")
                    continue

                signal = HackSignal(
                    raw_text=enriched_text,
                    source=SourceType.TWITTER,
                    source_id=f"tw:{tw.id}",
                    source_url=f"https://x.com/{tw.username}/status/{tw.id}",
                    source_author=tw.username,
                    source_author_tier=tier,
                    published_at=tw.created_at,
                    protocol_name=merged.get("protocol_name"),
                    chain=merged.get("chain"),
                    loss_usd=merged.get("loss_usd"),
                    tx_hash=merged.get("tx_hash"),
                    attacker_address=merged.get("attacker_address"),
                )

                inserted = self.store.insert(signal)
                if inserted:
                    count += 1
                    print(f"  🐦 [{handle}] {tw.text[:80]}...")

            self.consecutive_failures = 0
            return count

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                print(f"  429 rate limit for {handle} -- backing off")
                return -1  # caller handles backoff
            self.consecutive_failures += 1
            err_msg = str(e).split("for url")[0].strip()
            print(f"  Twitter error ({handle}): {err_msg}")
            if self.consecutive_failures >= 3:
                self._activate_fallback()
            return 0

        except Exception as e:
            self.consecutive_failures += 1
            err_msg = str(e).split("for url")[0].strip()
            print(f"  Twitter error ({handle}): {err_msg}")
            if self.consecutive_failures >= 3:
                self._activate_fallback()
            return 0

    # ── 전체 폴링 ──

    async def poll_all(self) -> int:
        if self.using_fallback:
            return await self._poll_via_xai()

        total = 0
        rate_limited = False
        async with httpx.AsyncClient(
            cookies=self._make_cookies(),
            headers=self._make_headers(),
            follow_redirects=True,
            timeout=30,
        ) as client:
            for tier_key, tier_accounts in self.accounts.items():
                tier_num = int(tier_key[-1]) if tier_key[-1].isdigit() else 2
                for acc in tier_accounts:
                    count = await self.poll_account(
                        client, acc["handle"], tier_num
                    )
                    if count == -1:
                        rate_limited = True
                        break  # 429 → 이번 사이클 즉시 중단
                    total += count
                    await asyncio.sleep(5)
                if rate_limited:
                    break
        return -1 if rate_limited else total

    async def start(self, interval: int = 300):
        """polling loop with exponential backoff on 429"""
        base_interval = interval
        current_interval = interval
        n_accounts = sum(len(v) for v in self.accounts.values())
        print(f"Twitter polling start ({n_accounts} accounts, {interval}s interval)")
        for tier_key, accs in self.accounts.items():
            for acc in accs:
                print(f"   - @{acc['handle']} ({tier_key})")

        print("  First poll will auto-set last_ids.")

        from datetime import datetime as _dt

        while True:
            try:
                now = _dt.now().strftime("%H:%M:%S")
                count = await self.poll_all()
                if count == -1:
                    # 429 rate limit: exponential backoff
                    current_interval = min(current_interval * 2, 1800)
                    print(f"  [{now}] 429 backoff: next poll in {current_interval}s")
                elif count > 0:
                    current_interval = base_interval
                    print(f"  [{now}] {count} new tweets stored")
                else:
                    current_interval = base_interval
                    print(f"  [{now}] No new tweets -- next in {current_interval}s")
            except Exception as e:
                print(f"  Poll loop error: {e}")
            await asyncio.sleep(current_interval)


    # ── xAI 폴백 ──

    XAI_DAILY_CAP = 0.50  # $0.50/일 예산 cap
    XAI_COST_PER_CALL = 0.005  # 대략적 비용 추정 ($0.005/call)

    def _activate_fallback(self):
        if not self.using_fallback:
            self.using_fallback = True
            print("🔄 Twitter 연속 3회 실패 → xAI 폴백 활성화")

    def _get_xai_budget_path(self) -> Path:
        return PROJECT_ROOT / "xai_budget.json"

    def _check_budget(self) -> bool:
        """일일 예산 체크. 초과 시 False."""
        budget_path = self._get_xai_budget_path()
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        if budget_path.exists():
            with open(budget_path) as f:
                data = json.load(f)
            if data.get("date") == today:
                spent = data.get("spent", 0)
                if spent >= self.XAI_DAILY_CAP:
                    return False
        return True

    def _record_spend(self, amount: float):
        """지출 기록."""
        budget_path = self._get_xai_budget_path()
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        data = {"date": today, "spent": 0, "calls": 0}
        if budget_path.exists():
            with open(budget_path) as f:
                existing = json.load(f)
            if existing.get("date") == today:
                data = existing

        data["spent"] = data.get("spent", 0) + amount
        data["calls"] = data.get("calls", 0) + 1

        with open(budget_path, "w") as f:
            json.dump(data, f, indent=2)

    async def _poll_via_xai(self) -> int:
        """xAI Grok x_search 폴백 — 보안 키워드로 트윗 검색."""
        try:
            from src.config import get_xai_client
            client = get_xai_client()
        except RuntimeError:
            print("  ⚠️ XAI_API_KEY 미설정 — 폴백 스킵")
            return 0

        if not self._check_budget():
            print("  💰 xAI 일일 예산 초과 ($0.50) — 스킵")
            return 0

        # 보안 관련 검색 쿼리
        queries = [
            "crypto hack exploit drained stolen funds",
            "DeFi protocol exploited vulnerability attack",
        ]

        total = 0
        for query in queries:
            try:
                response = await asyncio.to_thread(
                    client.chat.completions.create,
                    model="grok-3",
                    messages=[{
                        "role": "user",
                        "content": (
                            f"Search X/Twitter for recent posts (last 30 minutes) about: {query}\n\n"
                            "Return ONLY a JSON array of objects with these fields:\n"
                            "- username: the @handle\n"
                            "- text: full tweet text\n"
                            "- tweet_id: the tweet ID (number)\n"
                            "- url: full tweet URL\n\n"
                            "If no relevant results found, return an empty array [].\n"
                            "Response must be valid JSON only, no markdown."
                        ),
                    }],
                    search_parameters={"mode": "on", "sources": [{"type": "x"}]},
                )

                self._record_spend(self.XAI_COST_PER_CALL)

                content = response.choices[0].message.content or "[]"
                # JSON 파싱 (마크다운 코드블록 제거)
                content = content.strip()
                if content.startswith("```"):
                    content = content.split("\n", 1)[1]
                    content = content.rsplit("```", 1)[0]

                try:
                    tweets = json.loads(content)
                except json.JSONDecodeError:
                    logger.warning(f"xAI 응답 파싱 실패: {content[:100]}")
                    continue

                if not isinstance(tweets, list):
                    continue

                for tw in tweets:
                    text = tw.get("text", "")
                    username = tw.get("username", "xai_search")
                    tweet_id = str(tw.get("tweet_id", ""))
                    url = tw.get("url", "")

                    if not text:
                        continue

                    skip, _ = should_skip(text)
                    if skip:
                        continue

                    fields = extract_all(text)
                    signal = HackSignal(
                        raw_text=text,
                        source=SourceType.TWITTER,
                        source_id=f"xai:{tweet_id}" if tweet_id else f"xai:{hash(text)}",
                        source_url=url,
                        source_author=username,
                        source_author_tier=2,
                        published_at=datetime.now(timezone.utc),
                        protocol_name=fields["protocol_name"],
                        chain=fields["chain"],
                        loss_usd=fields["loss_usd"],
                        tx_hash=fields["tx_hash"],
                        attacker_address=fields["attacker_address"],
                    )

                    inserted = self.store.insert(signal)
                    if inserted:
                        total += 1
                        print(f"  🤖 [xAI] @{username}: {text[:60]}...")

            except Exception as e:
                print(f"  ⚠️ xAI 검색 실패: {str(e)[:80]}")

        # 폴백 → 원래로 복귀 시도 (다음 사이클에서 GraphQL 재시도)
        self.using_fallback = False
        self.consecutive_failures = 0

        return total

