from __future__ import annotations

import copy
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest

from scripts import generate, validate


def repository_files() -> dict[str, list[dict]]:
    return {
        filename: validate.load_jsonl(validate.ROOT / "data" / filename)
        for filename in validate.COLLECTIONS
    }


class V5CollectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.files = repository_files()

    def test_repository_v5_collections_reconcile(self) -> None:
        validate.validate_v5_collections(copy.deepcopy(self.files))

    def test_aggregate_count_mismatch_fails(self) -> None:
        files = copy.deepcopy(self.files)
        files["evidence-sets.jsonl"][1]["withheld_count"] = 112

        with self.assertRaisesRegex(validate.ValidationError, "member count does not reconcile"):
            validate.validate_v5_collections(files)

    def test_evidence_set_contract_change_fails(self) -> None:
        files = copy.deepcopy(self.files)
        safe_set = next(row for row in files["evidence-sets.jsonl"] if row["id"] == "set-v5-urlquery-safe")
        safe_set["set_type"] = "aggregate"

        with self.assertRaisesRegex(validate.ValidationError, "run/claim/type/collection contract changed"):
            validate.validate_v5_collections(files)

    def test_aggregate_only_record_cannot_expose_receipt_id(self) -> None:
        files = copy.deepcopy(self.files)
        files["evidence-sets.jsonl"][3]["notes"] += " 00000000-0000-0000-0000-000000000000"

        with self.assertRaisesRegex(validate.ValidationError, "exposes a locator or receipt ID"):
            validate.validate_v5_collections(files)

    def test_raw_submitted_path_publication_fails(self) -> None:
        files = copy.deepcopy(self.files)
        files["urlquery-receipts.jsonl"][0]["raw_submitted_path_published"] = True

        with self.assertRaisesRegex(validate.ValidationError, "raw submitted path must remain unpublished"):
            validate.validate_v5_collections(files)

    def test_displayed_author_cannot_be_authenticated(self) -> None:
        files = copy.deepcopy(self.files)
        files["iowa-objects.jsonl"][0]["author_label_authenticated"] = True

        with self.assertRaisesRegex(validate.ValidationError, "must remain unauthenticated"):
            validate.validate_v5_collections(files)

    def test_malformed_urlquery_locator_fails(self) -> None:
        files = copy.deepcopy(self.files)
        receipt = files["urlquery-receipts.jsonl"][0]
        url_row = next(row for row in files["urls.jsonl"] if row["id"] == receipt["url_id"])
        url_row["url"] += "?payload=1"

        with self.assertRaisesRegex(validate.ValidationError, "malformed or mismatched URLQuery"):
            validate.validate_v5_collections(files)

    def test_sqlite_v5_views_match_canonical_counts(self) -> None:
        connection = sqlite3.connect(generate.DATABASE)
        try:
            self.assertEqual(connection.execute("SELECT count(*) FROM iowa_object_inventory").fetchone()[0], 120)
            self.assertEqual(connection.execute("SELECT count(*) FROM urlquery_receipt_inventory").fetchone()[0], 1496)
            self.assertEqual(connection.execute("SELECT count(*) FROM v5_inventory_summary").fetchone()[0], 4)
        finally:
            connection.close()

    def test_generated_database_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_directory:
            database_path = Path(temp_directory) / "evidence.sqlite3"
            shutil.copy2(generate.DATABASE, database_path)
            connection = sqlite3.connect(database_path)
            try:
                connection.execute(
                    "UPDATE urlquery_receipts SET notes = notes || ' changed' WHERE id = (SELECT id FROM urlquery_receipts LIMIT 1)"
                )
                connection.commit()
            finally:
                connection.close()

            with self.assertRaisesRegex(validate.ValidationError, "urlquery_receipts differs from canonical JSONL"):
                validate.validate_generated_database(self.files, database_path)


if __name__ == "__main__":
    unittest.main()
