import unittest

from src.classifiers.gemini_classifier import (
    ClassificationResult,
    GeminiClassifier,
    build_classification_input,
    merge_results,
    should_veto_signal,
)


class GeminiClassifierLogicTest(unittest.TestCase):
    def test_model_input_keeps_more_than_legacy_4000_chars(self):
        text = "A" * 6000

        built = build_classification_input(text)

        self.assertEqual(built, text)
        self.assertGreater(len(built), 4000)

    def test_model_input_preserves_head_and_tail_when_long(self):
        text = "H" * 9000 + "M" * 9000 + "T" * 9000

        built = build_classification_input(text)

        self.assertLess(len(built), len(text))
        self.assertTrue(built.startswith("H" * 100))
        self.assertTrue(built.endswith("T" * 100))
        self.assertIn("omitted", built)

    def test_repair_rejects_semantically_invalid_required_fields(self):
        raw = '{"is_hack": false, "is_new_incident": true, "confidence": 1.5, "category": "other", "summary": "x"}'

        self.assertIsNone(GeminiClassifier._repair_json(raw))

    def test_repair_nulls_invalid_optional_hashes(self):
        raw = '{"is_hack": true, "is_new_incident": true, "confidence": 0.9, "category": "hack", "summary": "x", "tx_hash": "0x123", "attacker_address": "0x456"}'

        data = GeminiClassifier._repair_json(raw)

        self.assertIsNotNone(data)
        self.assertIsNone(data["tx_hash"])
        self.assertIsNone(data["attacker_address"])

    def test_llm_false_negative_cannot_veto_deterministic_tx_evidence(self):
        result = ClassificationResult(is_hack=False, is_new_incident=False, confidence=0.99, category="other")
        fields = {"tx_hash": "0x" + "a" * 64, "loss_usd": None, "attacker_address": None}

        veto, reason = should_veto_signal(result, fields, "Protocol exploited tx 0x" + "a" * 64)

        self.assertFalse(veto)
        self.assertEqual(reason, "")

    def test_llm_high_confidence_noise_can_veto_when_no_evidence(self):
        result = ClassificationResult(is_hack=False, is_new_incident=False, confidence=0.99, category="other")
        fields = {"tx_hash": None, "loss_usd": None, "attacker_address": None}

        veto, reason = should_veto_signal(result, fields, "weekly grant update and community event")

        self.assertTrue(veto)
        self.assertEqual(reason, "llm_not_hack(other)")

    def test_merge_normalizes_confident_llm_chain_when_regex_missing(self):
        result = ClassificationResult(is_hack=True, is_new_incident=True, confidence=0.9, category="exploit", chain="BNB Chain")

        merged = merge_results({"chain": None}, result)

        self.assertEqual(merged["chain"], "bsc")

    def test_merge_does_not_replace_regex_protocol_with_llm(self):
        result = ClassificationResult(is_hack=True, is_new_incident=True, confidence=0.99, category="exploit", protocol_name="Wrong Protocol")

        merged = merge_results({"protocol_name": "Radiant Capital"}, result)

        self.assertEqual(merged["protocol_name"], "Radiant Capital")

    def test_merge_rejects_low_confidence_llm_entity_fill(self):
        result = ClassificationResult(is_hack=True, is_new_incident=True, confidence=0.4, category="exploit", protocol_name="Radiant", chain="BNB Chain")

        merged = merge_results({"protocol_name": None, "chain": None}, result)

        self.assertIsNone(merged["protocol_name"])
        self.assertIsNone(merged["chain"])


if __name__ == "__main__":
    unittest.main()
