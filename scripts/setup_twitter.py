"""Twitter 쿠키 등록 — cookies.json 생성 (1회 실행)

사용법:
  source .venv/bin/activate
  python scripts/setup_twitter.py
"""
import asyncio
import json
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).parent.parent))

BEARER = (
    "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs"
    "%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
)
COOKIES_PATH = Path(__file__).parent.parent / "cookies.json"


async def setup():
    print()
    print("🐦 Twitter 쿠키 등록")
    print("=" * 60)
    print()
    print("📋 쿠키 추출 방법 (Chrome)")
    print()
    print("  1. x.com에 로그인 (구글 로그인 OK)")
    print("  2. F12 → Network 탭")
    print("  3. 페이지 새로고침 (F5)")
    print("  4. 요청 클릭 → Headers → Request Headers → Cookie:")
    print("     → 값 전체 우클릭 → Copy value")
    print()
    print("  ✅ auth_token=... 이 포함되어야 합니다!")
    print()
    print("=" * 60)
    print()

    raw = input("쿠키 문자열 붙여넣기: ").strip()
    if raw.startswith(("'", '"')) and raw.endswith(("'", '"')):
        raw = raw[1:-1]

    if not raw:
        print("❌ 쿠키 비어있음")
        return

    # 파싱: "key1=val1; key2=val2" → dict
    cookies = {}
    for part in raw.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()

    if "auth_token" not in cookies:
        print("❌ auth_token 없음! Network 탭에서 복사했는지 확인하세요.")
        return
    if "ct0" not in cookies:
        print("❌ ct0 없음!")
        return

    # cookies.json 저장 (auth_token + ct0만)
    save = {"auth_token": cookies["auth_token"], "ct0": cookies["ct0"]}
    with open(COOKIES_PATH, "w") as f:
        json.dump(save, f, indent=2)
    print(f"\n✅ cookies.json 저장 완료 → {COOKIES_PATH}")

    # 테스트
    print("\n📡 테스트: @PeckShieldAlert...")
    print("-" * 60)

    headers = {
        "authorization": f"Bearer {BEARER}",
        "x-csrf-token": save["ct0"],
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    }
    http_cookies = {"auth_token": save["auth_token"], "ct0": save["ct0"]}

    async with httpx.AsyncClient(
        cookies=http_cookies, headers=headers, follow_redirects=True
    ) as client:
        try:
            variables = json.dumps({
                "screen_name": "PeckShieldAlert",
                "withSafetyModeUserFields": True,
            })
            features = json.dumps({
                "hidden_profile_subscriptions_enabled": True,
                "rweb_tipjar_consumption_enabled": True,
                "responsive_web_graphql_exclude_directive_enabled": True,
                "verified_phone_label_enabled": False,
                "responsive_web_graphql_skip_user_profile_image_extensions_enabled": False,
                "responsive_web_graphql_timeline_navigation_enabled": True,
            })
            rep = await client.get(
                "https://x.com/i/api/graphql/Yka-W8dz7RaEuQNkroPkYw/UserByScreenName",
                params={"variables": variables, "features": features}
            )
            if rep.status_code == 200:
                user = rep.json()["data"]["user"]["result"]["legacy"]
                print(f"  👤 @{user['screen_name']} (followers: {user['followers_count']:,})")
                print()
                print("🎉 성공! python -m src.main listen 으로 가동!")
            else:
                print(f"  ❌ 응답 {rep.status_code}: {rep.text[:100]}")
                print("  쿠키가 만료되지 않았는지 확인하세요.")
        except Exception as e:
            print(f"  ❌ 테스트 실패: {e}")


if __name__ == "__main__":
    asyncio.run(setup())
