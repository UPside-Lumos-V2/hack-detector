import unittest
from datetime import datetime, timezone
from typing import Any, cast
from uuid import uuid4

from supabase import Client

from src.grouper import IncidentGrouper, _author_key, _merge_authors, _tier_counts
from src.models import HackSignal, SourceType


def _as_client(fake: "FakeSupabaseClient") -> Client:
    return cast(Client, cast(object, fake))


# ── Minimal in-memory Supabase fake ───────────────────────────────────────────

class _FakeResult:
    def __init__(self, data: list[dict[str, Any]]) -> None:
        self.data: list[dict[str, Any]] = data


class _FakeBuilder:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows
        self._mode: str | None = None
        self._insert_data: dict[str, Any] | None = None
        self._update_data: dict[str, Any] | None = None
        self._filters: list[tuple[str, str, Any]] = []
        self._order_field: str | None = None
        self._order_desc: bool = False
        self._limit_n: int | None = None

    def select(self, *_: Any) -> "_FakeBuilder":
        self._mode = "select"
        return self

    def insert(self, data: dict[str, Any]) -> "_FakeBuilder":
        self._mode = "insert"
        self._insert_data = data
        return self

    def update(self, data: dict[str, Any]) -> "_FakeBuilder":
        self._mode = "update"
        self._update_data = data
        return self

    def eq(self, field: str, value: Any) -> "_FakeBuilder":
        self._filters.append(("eq", field, value))
        return self

    def gte(self, field: str, value: Any) -> "_FakeBuilder":
        self._filters.append(("gte", field, value))
        return self

    def order(self, field: str, desc: bool = False) -> "_FakeBuilder":
        self._order_field = field
        self._order_desc = desc
        return self

    def limit(self, n: int) -> "_FakeBuilder":
        self._limit_n = n
        return self

    def _matches(self, row: dict[str, Any]) -> bool:
        for op, field, value in self._filters:
            rv = row.get(field)
            if op == "eq" and rv != value:
                return False
            if op == "gte" and (rv is None or rv < value):
                return False
        return True

    def execute(self) -> _FakeResult:
        if self._mode == "select":
            matched = [r for r in self._rows if self._matches(r)]
            if self._order_field:
                order_field = self._order_field
                matched.sort(
                    key=lambda r: cast(str, r.get(order_field) or ""),
                    reverse=self._order_desc,
                )
            if self._limit_n is not None:
                matched = matched[: self._limit_n]
            return _FakeResult(matched)

        if self._mode == "insert":
            assert self._insert_data is not None
            row: dict[str, Any] = {**self._insert_data, "id": str(uuid4())}
            self._rows.append(row)
            return _FakeResult([row])

        if self._mode == "update":
            assert self._update_data is not None
            for row in self._rows:
                if self._matches(row):
                    row.update(self._update_data)
            return _FakeResult([])

        return _FakeResult([])


class FakeSupabaseClient:
    def __init__(self) -> None:
        self._tables: dict[str, list[dict[str, Any]]] = {}

    def table(self, name: str) -> _FakeBuilder:
        if name not in self._tables:
            self._tables[name] = []
        return _FakeBuilder(self._tables[name])

    def groups(self) -> list[dict[str, Any]]:
        return self._tables.get("lumos_incident_groups", [])


# ── Signal factory ─────────────────────────────────────────────────────────────

def _signal(
    *,
    protocol_name: str = "TestProtocol",
    tx_hash: str | None = None,
    source_author: str = "cryptalert",
    source_author_tier: int = 2,
    source: SourceType = SourceType.TWITTER,
    published_at: datetime | None = None,
) -> HackSignal:
    return HackSignal(
        raw_text="Hack confirmed",
        source=source,
        source_id=f"{source.value}:{uuid4()}",
        source_url="https://example.com",
        source_author=source_author,
        source_author_tier=source_author_tier,
        published_at=published_at or datetime.now(timezone.utc),
        protocol_name=protocol_name,
        tx_hash=tx_hash,
    )


# ── Helper unit tests ──────────────────────────────────────────────────────────

class AuthorKeyTest(unittest.TestCase):
    def test_normalizes_case_and_whitespace(self):
        sig = _signal(source_author="  CryptAlert  ", source=SourceType.TWITTER)
        self.assertEqual(_author_key(sig), "twitter:cryptalert")

    def test_blank_author_returns_empty(self):
        sig = _signal(source_author="")
        self.assertEqual(_author_key(sig), "")

    def test_telegram_source_prefix(self):
        sig = _signal(source_author="CertikAlert", source=SourceType.TELEGRAM)
        self.assertEqual(_author_key(sig), "telegram:certikalert")


class MergeAuthorsTest(unittest.TestCase):
    def test_adds_new_author_to_empty_list(self):
        sig = _signal(source_author="alice", source_author_tier=2)
        self.assertEqual(_merge_authors([], sig), ["twitter:alice:2"])

    def test_deduplicates_same_author(self):
        existing = ["twitter:alice:2"]
        sig = _signal(source_author="alice", source_author_tier=2)
        result = _merge_authors(existing, sig)
        self.assertEqual(len(result), 1)
        self.assertIn("twitter:alice:2", result)

    def test_upgrades_to_better_tier(self):
        existing = ["twitter:alice:2"]
        sig = _signal(source_author="alice", source_author_tier=1)
        self.assertEqual(_merge_authors(existing, sig), ["twitter:alice:1"])

    def test_does_not_downgrade_tier(self):
        existing = ["twitter:alice:1"]
        sig = _signal(source_author="alice", source_author_tier=2)
        self.assertEqual(_merge_authors(existing, sig), ["twitter:alice:1"])

    def test_skips_blank_author(self):
        sig = _signal(source_author="")
        existing = ["twitter:alice:1"]
        self.assertEqual(_merge_authors(existing, sig), existing)

    def test_two_different_authors_both_appear(self):
        sig_a = _signal(source_author="alice", source_author_tier=1)
        sig_b = _signal(source_author="bob", source_author_tier=2)
        after_a = _merge_authors([], sig_a)
        after_b = _merge_authors(after_a, sig_b)
        self.assertEqual(len(after_b), 2)


class TierCountsTest(unittest.TestCase):
    def test_correct_counts(self):
        authors = ["twitter:alice:1", "telegram:bob:2", "twitter:carol:1"]
        t1, t2 = _tier_counts(authors)
        self.assertEqual(t1, 2)
        self.assertEqual(t2, 1)

    def test_empty_list(self):
        self.assertEqual(_tier_counts([]), (0, 0))

    def test_tier3_not_counted_in_t1_or_t2(self):
        authors = ["twitter:alice:3"]
        t1, t2 = _tier_counts(authors)
        self.assertEqual(t1, 0)
        self.assertEqual(t2, 0)


# ── Integration tests with fake grouper ───────────────────────────────────────

class GrouperAuthorIntegrationTest(unittest.TestCase):
    def test_same_author_three_signals_signal_count_3_author_count_1(self):
        client = FakeSupabaseClient()
        grouper = IncidentGrouper(_as_client(client))

        tx = "0x" + "a" * 64
        for _ in range(3):
            grouper.match_or_create(_signal(tx_hash=tx, source_author="securealerts", source_author_tier=2))

        groups = client.groups()
        self.assertEqual(len(groups), 1)
        g = groups[0]
        self.assertEqual(g["signal_count"], 3)
        self.assertEqual(g["source_author_count"], 1)
        self.assertEqual(len(g["source_authors"]), 1)

    def test_two_distinct_same_platform_authors_author_count_2(self):
        client = FakeSupabaseClient()
        grouper = IncidentGrouper(_as_client(client))

        now = datetime.now(timezone.utc)
        grouper.match_or_create(_signal(source_author="alice", source_author_tier=1, published_at=now))
        grouper.match_or_create(_signal(source_author="bob", source_author_tier=2, published_at=now))

        groups = client.groups()
        self.assertEqual(len(groups), 1)
        g = groups[0]
        self.assertEqual(g["signal_count"], 2)
        self.assertEqual(g["source_author_count"], 2)
        self.assertEqual(g["tier1_author_count"], 1)
        self.assertEqual(g["tier2_author_count"], 1)

    def test_signal_count_is_per_signal_not_unique_author(self):
        client = FakeSupabaseClient()
        grouper = IncidentGrouper(_as_client(client))

        tx = "0x" + "c" * 64
        for _ in range(3):
            grouper.match_or_create(_signal(tx_hash=tx, source_author="alice", source_author_tier=1))

        g = client.groups()[0]
        self.assertEqual(g["signal_count"], 3)
        self.assertEqual(g["source_author_count"], 1)
        self.assertNotEqual(g["signal_count"], g["source_author_count"])

    def test_same_author_tier_upgrade_tracked_on_repost(self):
        client = FakeSupabaseClient()
        grouper = IncidentGrouper(_as_client(client))

        tx = "0x" + "b" * 64
        grouper.match_or_create(_signal(tx_hash=tx, source_author="securealerts", source_author_tier=2))
        grouper.match_or_create(_signal(tx_hash=tx, source_author="securealerts", source_author_tier=1))

        g = client.groups()[0]
        self.assertEqual(g["source_author_count"], 1)
        self.assertEqual(g["tier1_author_count"], 1)
        self.assertEqual(g["tier2_author_count"], 0)

    def test_blank_source_author_handled_without_crash(self):
        client = FakeSupabaseClient()
        grouper = IncidentGrouper(_as_client(client))

        tx = "0x" + "d" * 64
        grouper.match_or_create(_signal(tx_hash=tx, source_author="", source_author_tier=2))
        grouper.match_or_create(_signal(tx_hash=tx, source_author="", source_author_tier=2))

        g = client.groups()[0]
        self.assertEqual(g["signal_count"], 2)
        self.assertEqual(g["source_author_count"], 0)


if __name__ == "__main__":
    unittest.main()
