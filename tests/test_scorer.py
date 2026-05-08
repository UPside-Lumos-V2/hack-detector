"""Scorer contract tests."""

import unittest

from postgrest.types import JSON

from src.scorer import (
    CONFIDENCE_INPUT_FIELDS,
    CORROBORATION_INPUT_FIELDS,
    MAX_PLATFORM_AUTHOR_BONUS,
    METADATA_COMPLETENESS_SEVERITY_BONUS,
    RETROSPECTIVE_SEVERITY_CAP,
    SCORER_OUTPUT_FIELDS,
    SEVERITY_INPUT_FIELDS,
    TWO_AUTHOR_BONUS,
    calculate_corroboration,
    calculate_severity,
    severity_label_for_score,
)


class ScorerContractTest(unittest.TestCase):
    def test_severity_label_boundaries(self) -> None:
        cases = {
            44: "low",
            45: "medium",
            69: "medium",
            70: "high",
            84: "high",
            85: "critical",
        }

        for score, expected in cases.items():
            with self.subTest(score=score):
                self.assertEqual(severity_label_for_score(score), expected)

    def test_scorer_output_contract(self) -> None:
        self.assertEqual(
            SCORER_OUTPUT_FIELDS,
            (
                "confidence_score",
                "corroboration_score",
                "severity_score",
                "severity_label",
            ),
        )

    def test_scoring_inputs_do_not_include_root_cause_terms(self) -> None:
        forbidden_terms = {"bridge", "oracle", "governance", "root_cause"}
        self.assertTrue(forbidden_terms.isdisjoint(CONFIDENCE_INPUT_FIELDS))


class SamePlatformAuthorCorroborationTest(unittest.TestCase):
    def _make_group(self, authors: list[str]) -> dict[str, JSON]:
        return {"source_authors": authors}

    def test_no_authors_returns_zero(self) -> None:
        self.assertEqual(calculate_corroboration(self._make_group([])), 0)

    def test_single_author_returns_zero(self) -> None:
        group = self._make_group(["twitter:alice_eth:1"])
        self.assertEqual(calculate_corroboration(group), 0)

    def test_two_distinct_same_platform_authors_get_bonus(self) -> None:
        group = self._make_group([
            "twitter:alice_eth:2",
            "twitter:bob_sec:2",
        ])
        self.assertEqual(calculate_corroboration(group), TWO_AUTHOR_BONUS)

    def test_repeated_same_author_posts_do_not_inflate_bonus(self) -> None:
        group = self._make_group([
            "twitter:alice_eth:2",
            "twitter:alice_eth:2",
            "twitter:alice_eth:2",
        ])
        self.assertEqual(calculate_corroboration(group), 0)

    def test_repeated_tier1_author_does_not_produce_tier1_bonus(self) -> None:
        group = self._make_group([
            "twitter:alice_eth:1",
            "twitter:alice_eth:1",
        ])
        self.assertEqual(calculate_corroboration(group), 0)

    def test_repeated_tier1_plus_one_tier2_gives_only_two_author_bonus(self) -> None:
        group = self._make_group([
            "twitter:alice_eth:1",
            "twitter:alice_eth:1",
            "twitter:bob_sec:2",
        ])
        self.assertEqual(calculate_corroboration(group), TWO_AUTHOR_BONUS)

    def test_repeated_author_mixed_with_distinct_counts_once(self) -> None:
        group = self._make_group([
            "twitter:alice_eth:2",
            "twitter:alice_eth:1",
            "twitter:bob_sec:2",
        ])
        self.assertEqual(calculate_corroboration(group), TWO_AUTHOR_BONUS)

    def test_three_distinct_same_platform_authors_get_higher_bonus(self) -> None:
        group = self._make_group([
            "twitter:alice_eth:2",
            "twitter:bob_sec:2",
            "twitter:charlie_dex:2",
        ])
        self.assertEqual(calculate_corroboration(group), 15)

    def test_many_authors_with_tier1_capped_at_max_platform_bonus(self) -> None:
        tier1_authors = [f"twitter:t1user{i}:1" for i in range(5)]
        tier2_authors = [f"twitter:t2user{i}:2" for i in range(15)]
        group = self._make_group(tier1_authors + tier2_authors)
        self.assertEqual(calculate_corroboration(group), MAX_PLATFORM_AUTHOR_BONUS)

    def test_two_tier1_same_platform_authors_add_tier1_bonus(self) -> None:
        group = self._make_group([
            "twitter:alice_eth:1",
            "twitter:bob_sec:1",
        ])
        self.assertEqual(calculate_corroboration(group), 15)

    def test_three_plus_authors_with_two_tier1_capped_at_max(self) -> None:
        group = self._make_group([
            "twitter:alice_eth:1",
            "twitter:bob_sec:1",
            "twitter:charlie_dex:2",
            "twitter:dave_nft:2",
            "twitter:eve_defi:2",
        ])
        self.assertEqual(calculate_corroboration(group), MAX_PLATFORM_AUTHOR_BONUS)

    def test_cross_platform_authors_scored_per_platform(self) -> None:
        group = self._make_group([
            "twitter:alice_eth:2",
            "telegram:charlie_dex:2",
        ])
        self.assertEqual(calculate_corroboration(group), 0)

    def test_same_platform_bonus_cannot_match_cross_platform_confirmation(self) -> None:
        cross_platform_bonus = 30
        self.assertLess(MAX_PLATFORM_AUTHOR_BONUS, cross_platform_bonus)

    def test_corroboration_input_fields_contract(self) -> None:
        self.assertEqual(
            CORROBORATION_INPUT_FIELDS,
            (
                "source_authors",
                "source_author_count",
                "tier1_author_count",
                "tier2_author_count",
            ),
        )

    def test_corroboration_input_fields_exclude_root_cause_terms(self) -> None:
        forbidden_terms = {"bridge", "oracle", "governance", "root_cause"}
        self.assertTrue(forbidden_terms.isdisjoint(CORROBORATION_INPUT_FIELDS))

    def test_missing_source_authors_field_returns_zero(self) -> None:
        group: dict[str, JSON] = {}
        self.assertEqual(calculate_corroboration(group), 0)


class SeverityScoreTest(unittest.TestCase):
    def _make_group(self, **kwargs: JSON) -> dict[str, JSON]:
        return dict(kwargs)

    def test_critical_large_active_exploit(self) -> None:
        group = self._make_group(
            llm_is_new_incident=True,
            loss_usd=15_000_000,
            tx_hash="0xabc123",
        )
        score, label = calculate_severity(group)
        self.assertGreaterEqual(score, 85)
        self.assertEqual(label, "critical")

    def test_retrospective_high_confidence_yields_low(self) -> None:
        group = self._make_group(
            llm_is_new_incident=False,
            llm_confidence=0.95,
            loss_usd=50_000_000,
            tx_hash="0xdeadbeef",
        )
        score, label = calculate_severity(group)
        self.assertEqual(label, "low")
        self.assertLessEqual(score, 44)
        self.assertEqual(score, RETROSPECTIVE_SEVERITY_CAP)

    def test_retrospective_capped_regardless_of_loss(self) -> None:
        group = self._make_group(
            llm_is_new_incident=False,
            loss_usd=100_000_000,
            tx_hash="0xabc",
            attacker_address="0xevil",
        )
        score, label = calculate_severity(group)
        self.assertEqual(score, RETROSPECTIVE_SEVERITY_CAP)
        self.assertEqual(label, "low")

    def test_unknown_loss_strong_identity_anchors_yields_medium(self) -> None:
        group = self._make_group(
            llm_is_new_incident=True,
            tx_hash="0xabc",
            attacker_address="0xevil",
        )
        score, label = calculate_severity(group)
        self.assertIn(label, ("medium", "high"))
        self.assertGreaterEqual(score, 45)

    def test_unknown_loss_all_anchors_tier1_yields_high(self) -> None:
        group = self._make_group(
            llm_is_new_incident=True,
            tx_hash="0xabc",
            attacker_address="0xevil",
            protocol_name="Uniswap",
            best_tier=1,
        )
        score, label = calculate_severity(group)
        self.assertGreaterEqual(score, 70)
        self.assertIn(label, ("high", "critical"))

    def test_unknown_newness_scores_lower_than_confirmed_active(self) -> None:
        group_none = self._make_group(llm_is_new_incident=None, tx_hash="0xabc")
        group_true = self._make_group(llm_is_new_incident=True, tx_hash="0xabc")
        score_none, _ = calculate_severity(group_none)
        score_true, _ = calculate_severity(group_true)
        self.assertLess(score_none, score_true)

    def test_active_no_loss_no_anchors_stays_low(self) -> None:
        group = self._make_group(llm_is_new_incident=True)
        score, label = calculate_severity(group)
        self.assertLessEqual(score, 44)
        self.assertEqual(label, "low")

    def test_medium_loss_active_no_anchors_yields_medium(self) -> None:
        group = self._make_group(llm_is_new_incident=True, loss_usd=1_000_000)
        score, label = calculate_severity(group)
        self.assertIn(label, ("medium", "high"))
        self.assertGreaterEqual(score, 45)

    def test_bounded_corroboration_can_raise_active_severity(self) -> None:
        weak = self._make_group(llm_is_new_incident=True, tx_hash="0xabc", attacker_address="0xevil")
        strong = self._make_group(
            llm_is_new_incident=True,
            tx_hash="0xabc",
            attacker_address="0xevil",
            corroboration_score=20,
        )

        weak_score, weak_label = calculate_severity(weak)
        strong_score, strong_label = calculate_severity(strong)

        self.assertEqual(weak_label, "medium")
        self.assertEqual(strong_label, "high")
        self.assertEqual(strong_score - weak_score, 10)

    def test_retrospective_cap_ignores_corroboration(self) -> None:
        group = self._make_group(
            llm_is_new_incident=False,
            loss_usd=50_000_000,
            tx_hash="0xabc",
            corroboration_score=100,
        )

        score, label = calculate_severity(group)

        self.assertEqual(score, RETROSPECTIVE_SEVERITY_CAP)
        self.assertEqual(label, "low")

    def test_severity_input_fields_include_corroboration_not_confidence(self) -> None:
        self.assertIn("corroboration_score", SEVERITY_INPUT_FIELDS)
        self.assertNotIn("confidence_score", SEVERITY_INPUT_FIELDS)

    def test_metadata_completeness_adds_bounded_severity_bonus(self) -> None:
        partial = self._make_group(llm_is_new_incident=True, tx_hash="0xabc", attacker_address="0xevil")
        complete = self._make_group(
            llm_is_new_incident=True,
            tx_hash="0xabc",
            attacker_address="0xevil",
            protocol_name="Uniswap",
            chain="ethereum",
        )

        partial_score, _ = calculate_severity(partial)
        complete_score, _ = calculate_severity(complete)

        self.assertEqual(complete_score - partial_score, 5 + METADATA_COMPLETENESS_SEVERITY_BONUS)

    def test_severity_input_fields_include_metadata_completeness_fields(self) -> None:
        self.assertIn("chain", SEVERITY_INPUT_FIELDS)
        self.assertIn("protocol_name", SEVERITY_INPUT_FIELDS)
        self.assertIn("attacker_address", SEVERITY_INPUT_FIELDS)

    def test_severity_input_fields_exclude_root_cause_terms(self) -> None:
        forbidden = {"bridge", "oracle", "governance", "root_cause"}
        self.assertTrue(forbidden.isdisjoint(SEVERITY_INPUT_FIELDS))

    def test_severity_score_clamped_to_100(self) -> None:
        group = self._make_group(
            llm_is_new_incident=True,
            loss_usd=500_000_000,
            tx_hash="0xabc",
            attacker_address="0xevil",
            protocol_name="Compound",
            best_tier=1,
        )
        score, _ = calculate_severity(group)
        self.assertLessEqual(score, 100)
        self.assertGreaterEqual(score, 0)


if __name__ == "__main__":
    _ = unittest.main()
