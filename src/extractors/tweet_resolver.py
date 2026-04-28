"""
Tweet URL Resolver — fxtwitter API로 트윗 URL에서 내용을 가져온다.

Telegram 메시지나 트윗 안에 다른 트윗 링크가 있으면,
fxtwitter.com API로 전문(full_text)을 가져와서 raw_text에 append.

fxtwitter API는 인증 불필요, rate limit 관대.
"""
import re
import logging

import httpx

logger = logging.getLogger(__name__)

# twitter.com, x.com, fxtwitter.com, vxtwitter.com 전부 매칭
TWEET_URL_RE = re.compile(
    r"https?://(?:twitter\.com|x\.com|fxtwitter\.com|vxtwitter\.com)"
    r"/(\w+)/status/(\d+)",
)

# fxtwitter API 엔드포인트
_API_BASE = "https://api.fxtwitter.com"
_TIMEOUT = 10


def find_tweet_urls(text: str) -> list[tuple[str, str]]:
    """텍스트에서 트윗 URL을 모두 찾아 (username, tweet_id) 리스트로 반환."""
    return TWEET_URL_RE.findall(text)


async def resolve_single(
    client: httpx.AsyncClient, username: str, tweet_id: str
) -> str | None:
    """단일 트윗의 전문을 fxtwitter API로 가져온다."""
    url = f"{_API_BASE}/{username}/status/{tweet_id}"
    try:
        resp = await client.get(url, timeout=_TIMEOUT)
        if resp.status_code != 200:
            logger.warning(f"fxtwitter {resp.status_code} for {tweet_id}")
            return None

        data = resp.json()
        tweet = data.get("tweet", {})
        text = tweet.get("text", "")
        author = tweet.get("author", {}).get("screen_name", username)

        if not text:
            return None

        return f"[@{author}] {text}"

    except (httpx.HTTPError, Exception) as e:
        logger.warning(f"fxtwitter resolve failed ({tweet_id}): {e}")
        return None


async def resolve_tweet_urls(text: str) -> list[str]:
    """
    텍스트 안의 모든 트윗 URL을 resolve해서 내용 리스트 반환.
    결과가 없으면 빈 리스트.
    """
    matches = find_tweet_urls(text)
    if not matches:
        return []

    results: list[str] = []
    async with httpx.AsyncClient(
        headers={"User-Agent": "hack-detector/0.5"},
        follow_redirects=True,
    ) as client:
        for username, tweet_id in matches[:3]:  # 최대 3개까지만
            resolved = await resolve_single(client, username, tweet_id)
            if resolved:
                results.append(resolved)

    return results


def append_resolved_to_text(original: str, resolved: list[str]) -> str:
    """resolve된 트윗 내용을 원본 텍스트에 번호 매겨서 append."""
    if not resolved:
        return original
    parts = []
    for i, text in enumerate(resolved, 1):
        parts.append(f"\n\n--- Referenced Tweet {i} ---\n{text}")
    return original + "".join(parts)
