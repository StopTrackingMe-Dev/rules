import copy
import json
import unittest
from pathlib import Path

from tools.build_rules import ValidationError, validate_rule


class FingerprintAlternativesTest(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).resolve().parents[1] / "rules/bilibili.json"
        self.rule = json.loads(path.read_text(encoding="utf-8"))["rules"][0]

    def test_updated_and_legacy_rules_validate(self):
        validate_rule(self.rule, "bilibili")
        del self.rule["sharePanelFingerprintAlternatives"]
        validate_rule(self.rule, "bilibili")

    def test_rejects_malformed_or_unbounded_alternatives(self):
        selector = {"textRegex": "share"}
        invalid = [None, {}, [], [None], [{}], [[]], [[{}]],
                   [[{"clickable": True}]], [[{"textRegex": "(?=share)"}]],
                   [[{"script": "click()"}]], [[selector]] * 8, [[selector] * 25]]
        for value in invalid:
            with self.subTest(value=value):
                self.rule["sharePanelFingerprintAlternatives"] = value
                with self.assertRaises(ValidationError):
                    validate_rule(self.rule, "bilibili")

    def test_accepts_maximum_group_count_and_size(self):
        self.rule["sharePanelFingerprintAlternatives"] = [
            [{"textRegex": "share"}] * 24
        ] * 7
        validate_rule(self.rule, "bilibili")

    def test_original_group_remains_required(self):
        rule = copy.deepcopy(self.rule)
        del rule["sharePanelFingerprint"]
        with self.assertRaises(ValidationError):
            validate_rule(rule, "bilibili")


if __name__ == "__main__":
    unittest.main()
