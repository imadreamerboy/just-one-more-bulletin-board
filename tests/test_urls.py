from __future__ import annotations

import unittest
from urllib.parse import urlsplit

from scripts import generate, validate


def url_record(url: str, *, risks: list[str] | None = None, safe: str = "yes") -> dict:
    return {
        "id": validate.exact_url_id(url),
        "url": url,
        "canonical_host": (urlsplit(url).hostname or "").lower().rstrip("."),
        "labels": [],
        "discovered_in": ["test"],
        "mention_count": 1,
        "risk_tags": risks or ["none"],
        "safe_to_open": safe,
        "notes": "",
    }


class ExactUrlTests(unittest.TestCase):
    def test_byte_distinct_variants_remain_distinct(self) -> None:
        urls = [
            "https://example.test/a//b?x=1&y=2#rev-1",
            "https://example.test/a/b?x=1&y=2#rev-1",
            "https://example.test/a//b?y=2&x=1#rev-1",
            "https://example.test/a//b?x=1&y=2#rev-2",
        ]
        rows = [url_record(url) for url in urls]

        validate.validate_url_records(rows)

        self.assertEqual(len({row["id"] for row in rows}), len(urls))

    def test_duplicate_exact_url_fails(self) -> None:
        row = url_record("https://example.test/object")

        with self.assertRaisesRegex(validate.ValidationError, "duplicate exact URL"):
            validate.validate_url_records([row, dict(row)])

    def test_mutating_url_requires_no_opening_guidance(self) -> None:
        row = url_record(
            "https://counter.example.test/value/up",
            risks=["mutating_endpoint"],
            safe="caution",
        )

        with self.assertRaisesRegex(validate.ValidationError, "mutating_endpoint/no"):
            validate.validate_url_records([row])

    def test_public_credential_url_is_allowed_when_labelled(self) -> None:
        row = url_record(
            "https://api.example.test/object?api_key=0123456789abcdef0123456789abcdef",
            risks=["credential"],
            safe="no",
        )

        validate.validate_url_records([row])

    def test_url_id_must_match_exact_value(self) -> None:
        row = url_record("https://example.test/object")
        row["id"] = "url-0000000000000000"

        with self.assertRaisesRegex(validate.ValidationError, "expected exact-URL ID"):
            validate.validate_url_records([row])

    def test_trailing_prose_is_rejected_as_extraction_debris(self) -> None:
        row = url_record("https://example.test/object)—plus")

        with self.assertRaisesRegex(validate.ValidationError, "extraction debris"):
            validate.validate_url_records([row])

    def test_longer_url_cannot_satisfy_missing_exact_report_entry(self) -> None:
        expected = url_record("https://example.test/object")
        longer = url_record("https://example.test/object-extra")
        report = "\n".join(
            [
                f"- {validate.code_span(longer['url'])}",
                f"  - ID `{longer['id']}`; opening `yes`",
            ]
        )

        with self.assertRaisesRegex(validate.ValidationError, "expected one entry"):
            validate.validate_url_report([expected], report)

    def test_code_span_handles_embedded_backticks(self) -> None:
        rendered = generate.code_span("https://example.test/a`b")

        self.assertEqual(rendered, "``https://example.test/a`b``")


if __name__ == "__main__":
    unittest.main()
