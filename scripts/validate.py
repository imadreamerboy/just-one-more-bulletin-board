#!/usr/bin/env python3
"""Validate the canonical JSONL collections and repository safety invariants."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schema" / "collections.schema.json"
DATABASE_PATH = ROOT / "data" / "evidence.sqlite3"
COLLECTIONS = {
    "entities.jsonl": "entity",
    "urls.jsonl": "url",
    "evidence-sets.jsonl": "evidence_set",
    "iowa-objects.jsonl": "iowa_object",
    "urlquery-receipts.jsonl": "urlquery_receipt",
    "sources.jsonl": "source",
    "claims.jsonl": "claim",
    "relations.jsonl": "relation",
    "runs.jsonl": "run",
    "search-events.jsonl": "search_event",
}
PRIVATE_PATH_PATTERNS = [
    re.compile(r"/Users/", re.IGNORECASE),
    re.compile(r"/home/", re.IGNORECASE),
    re.compile(r"/private/(?:tmp|var)/", re.IGNORECASE),
    re.compile(r"/var/folders/", re.IGNORECASE),
    re.compile(r"[A-Za-z]:\\Users\\", re.IGNORECASE),
    re.compile(r"agent-vault", re.IGNORECASE),
]
SECRET_PATTERNS = [
    re.compile(r"(?i)(?:api[_-]?key|access[_-]?token|authorization|bearer|secret)\s*[:=]\s*[^\s,;]{8,}"),
    re.compile(r"(?i)[?&](?:api[_-]?key|access[_-]?token|token|key)=[^&#\s]+"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(r"sk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?<![A-Za-z0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![A-Za-z0-9.])"),
]
MUTATING_SOURCE_PATTERNS = [
    re.compile(r"(?i)/(?:up|down|reset|hit|set)(?:/|\?|$)"),
    re.compile(r"(?i)[?&]action=(?:shorturl|delete|save)(?:&|$)"),
]
COLLUSION_REVISION_RE = re.compile(
    r"^https://collusion\.wiki/explorer/page/(?P<page>[^?#]+)\.html#rev-(?P<revision>[0-9]+)$"
)
URLQUERY_REPORT_RE = re.compile(
    r"^https://urlquery\.net/report/(?P<uuid>[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$"
)
LINUXIARZ_IOWA_RE = re.compile(r"^https://paste\.linuxiarz\.pl/view/(?P<object>[a-f0-9]{8})$")
STRONG_IOWA_OBJECTS = {
    "039c765a",
    "11263743",
    "40101f1a",
    "5a6af988",
    "8edd7eaa",
    "a924bfbc",
    "bdde46e6",
    "df40f1f1",
}
STRONG_IOWA_SEQUENCE = [
    "df40f1f1",
    "11263743",
    "bdde46e6",
    "8edd7eaa",
    "039c765a",
    "5a6af988",
    "a924bfbc",
    "40101f1a",
]
RSS_DATED_IOWA_OBJECTS = {"f800c8b1", "c0f58df5", "7a45b400"}
EXTRA_V5_PASTE_OBJECTS = {"0e185856", "1384eaa5", "eb4ebe8e", "f621ab2b", "5e2e9867", "43093dd9"}
URLQUERY_REPRESENTATIVE_SCOPES = {
    "exact-task-family-join": {
        "991e0a41-21f4-42bb-8d3f-97ae51194880",
        "9e7f2eb0-4b15-4439-a58f-bb1527e8ee69",
        "b658f273-fd60-4191-b496-d244d47d5531",
        "df249a18-9497-4707-af5c-aaf3552b3948",
        "a070fcd0-51c9-44f5-abd3-5b107d72464a",
        "69cd89cc-e804-4abc-814f-e39ada9eea90",
        "abfcb9e1-cc02-4414-ad3c-275d88f27927",
        "9bd18db2-42f1-4536-9520-fb34fe2d7cd5",
        "8c45dd93-439f-4e73-9e2a-d5f3b8d2e99c",
        "baa189ec-130b-4a60-9fdf-566b1c5f0377",
    },
    "representative-harness-telemetry": {
        "4de7cf8e-e138-4297-b861-cfd3783c6635",
        "288088df-74e9-4221-aa89-36831684d62b",
        "987193d5-2a80-491d-8021-44afb454a909",
        "6b44137a-f6c4-4308-8aeb-8e746c959904",
        "565ce8fa-00dd-4ee8-91d0-609fb1661009",
        "612c04e2-5f4b-4c12-b37a-00599b8274a3",
        "0c039b49-d9b4-4f9b-b946-5fa63b59e1c4",
        "34a84023-c846-4380-9d99-f11006cdcdb9",
    },
    "account-only-adjacency": {"0b76f662-ab2b-4cf4-9f69-45ee86ce715c"},
    "ordinary-or-unrelated": {"77c60b9f-aae5-4126-8c3b-b3ff1abe7c65"},
}


class ValidationError(Exception):
    pass


def exact_url_id(raw: str) -> str:
    return "url-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def code_span(value: str) -> str:
    longest = max((len(run) for run in re.findall(r"`+", value)), default=0)
    delimiter = "`" * max(1, longest + 1)
    return f"{delimiter}{value}{delimiter}"


def load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, start=1):
            if not raw.strip():
                raise ValidationError(f"{path.relative_to(ROOT)}:{line_number}: blank lines are not allowed")
            try:
                value = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValidationError(f"{path.relative_to(ROOT)}:{line_number}: {exc}") from exc
            if not isinstance(value, dict):
                raise ValidationError(f"{path.relative_to(ROOT)}:{line_number}: record must be an object")
            rows.append(value)
    return rows


def type_matches(value: object, expected: str) -> bool:
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(expected, False)


def validate_value(value: object, schema: dict, location: str) -> None:
    expected = schema.get("type")
    if expected:
        allowed = expected if isinstance(expected, list) else [expected]
        if not any(type_matches(value, item) for item in allowed):
            raise ValidationError(f"{location}: expected type {allowed}, got {type(value).__name__}")
        if value is None:
            return

    if "enum" in schema and value not in schema["enum"]:
        raise ValidationError(f"{location}: {value!r} is not in {schema['enum']}")

    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            raise ValidationError(f"{location}: string is too short")
        if pattern := schema.get("pattern"):
            if re.fullmatch(pattern, value) is None:
                raise ValidationError(f"{location}: {value!r} does not match {pattern}")
        if schema.get("format") == "uri":
            parsed = urlsplit(value)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValidationError(f"{location}: expected an HTTP(S) URI")
        if schema.get("format") == "date-time":
            try:
                datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValidationError(f"{location}: invalid ISO 8601 date-time") from exc

    if isinstance(value, int) and value < schema.get("minimum", value):
        raise ValidationError(f"{location}: value is below minimum {schema['minimum']}")

    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            raise ValidationError(f"{location}: array is too short")
        if schema.get("uniqueItems") and len({json.dumps(item, sort_keys=True) for item in value}) != len(value):
            raise ValidationError(f"{location}: array items must be unique")
        if item_schema := schema.get("items"):
            for index, item in enumerate(value):
                validate_value(item, item_schema, f"{location}[{index}]")

    if isinstance(value, dict):
        required = schema.get("required", [])
        missing = [key for key in required if key not in value]
        if missing:
            raise ValidationError(f"{location}: missing required fields {missing}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            extra = sorted(set(value) - set(properties))
            if extra:
                raise ValidationError(f"{location}: unexpected fields {extra}")
        for key, item in value.items():
            if key in properties:
                validate_value(item, properties[key], f"{location}.{key}")


def canonical_url(raw: str) -> str:
    parsed = urlsplit(raw)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port
    netloc = host if port in {None, 80 if scheme == "http" else 443} else f"{host}:{port}"
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunsplit((scheme, netloc, path, query, ""))


def validate_url_records(rows: list[dict]) -> None:
    seen_urls: set[str] = set()
    for row in rows:
        url = row["url"]
        if url in seen_urls:
            raise ValidationError(f"{row['id']}: duplicate exact URL")
        seen_urls.add(url)
        expected_id = exact_url_id(url)
        if row["id"] != expected_id:
            raise ValidationError(f"{row['id']}: expected exact-URL ID {expected_id}")
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValidationError(f"{row['id']}: URL must use HTTP(S) with a host")
        if re.search(r"[\s<>\[\]“”‘’—]", url) or url.count(")") > url.count("("):
            raise ValidationError(f"{row['id']}: URL contains likely extraction debris")
        canonical_host = (parsed.hostname or "").lower().rstrip(".")
        if canonical_host != row["canonical_host"]:
            raise ValidationError(f"{row['id']}: canonical_host does not match URL")
        risks = row["risk_tags"]
        if "none" in risks and len(risks) != 1:
            raise ValidationError(f"{row['id']}: risk tag 'none' cannot be combined with other tags")
        if any(pattern.search(url) for pattern in SECRET_PATTERNS):
            if not {"credential", "signed_token"}.intersection(risks):
                raise ValidationError(f"{row['id']}: credential-shaped URL requires a credential/token risk tag")
            if row["safe_to_open"] != "no":
                raise ValidationError(f"{row['id']}: credential/token URL must be marked no")
        if any(pattern.search(url) for pattern in MUTATING_SOURCE_PATTERNS):
            if "mutating_endpoint" not in risks or row["safe_to_open"] != "no":
                raise ValidationError(f"{row['id']}: mutating URL requires mutating_endpoint/no")
        if set(risks).intersection({"credential", "signed_token", "mutating_endpoint", "server_side_fetch"}) and row["safe_to_open"] != "no":
            raise ValidationError(f"{row['id']}: non-passive URL must be marked no")
        if "external_logging" in risks and row["safe_to_open"] == "yes":
            raise ValidationError(f"{row['id']}: external-logging URL cannot be marked yes")


def validate_safety(files: dict[str, list[dict]]) -> None:
    scrubbed_rows = []
    for filename, rows in files.items():
        for row in rows:
            scrubbed = dict(row)
            if filename == "urls.jsonl":
                scrubbed["url"] = "<published-url>"
            scrubbed_rows.append(scrubbed)
    serialised = "\n".join(json.dumps(row, sort_keys=True) for row in scrubbed_rows)
    for pattern in PRIVATE_PATH_PATTERNS:
        if match := pattern.search(serialised):
            raise ValidationError(f"private absolute path detected near {match.group(0)!r}")
    for pattern in SECRET_PATTERNS:
        if match := pattern.search(serialised):
            raise ValidationError(f"credential-shaped value detected near {match.group(0)[:40]!r}")

    validate_url_records(files["urls.jsonl"])

    for source in files["sources.jsonl"]:
        url = source["source_url"]
        risks = source["risk_tags"]
        if source["first_seen_at"] is None and source["first_seen_precision"] != "unknown":
            raise ValidationError(f"{source['id']}: null first_seen_at requires unknown precision")
        if source["first_seen_at"] is not None and source["first_seen_precision"] == "unknown":
            raise ValidationError(f"{source['id']}: known first_seen_at requires stated precision")
        if "none" in risks and len(risks) != 1:
            raise ValidationError(f"{source['id']}: risk tag 'none' cannot be combined with other tags")
        if source["safe_to_open"] == "no" and url is not None:
            raise ValidationError(f"{source['id']}: unsafe source URLs must be withheld")
        if source["publication_status"] == "public" and url is None:
            raise ValidationError(f"{source['id']}: public source requires a URL")
        if source["publication_status"] in {"private", "withheld"} and url is not None:
            raise ValidationError(f"{source['id']}: private or withheld source must not expose a URL")
        if url:
            parsed = urlsplit(url)
            if parsed.username or parsed.password:
                raise ValidationError(f"{source['id']}: source URL must not contain user information")
            if parsed.hostname != source["canonical_host"]:
                raise ValidationError(f"{source['id']}: canonical_host does not match source_url")
            if any(pattern.search(url) for pattern in MUTATING_SOURCE_PATTERNS):
                raise ValidationError(f"{source['id']}: source URL resembles a mutating endpoint")
            if source["evidence_type"] == "static_revision" and parsed.hostname == "collusion.wiki":
                match = COLLUSION_REVISION_RE.fullmatch(url)
                if not match:
                    raise ValidationError(f"{source['id']}: malformed collusion.wiki static revision URL")
                expected_revision = f"{match.group('page')}@{match.group('revision')}"
                if source["source_revision"] != expected_revision:
                    raise ValidationError(
                        f"{source['id']}: URL anchor does not match source_revision {source['source_revision']!r}"
                    )


def validate_repository_shape() -> None:
    allowed_data = {
        "claims.jsonl",
        "entities.jsonl",
        "evidence.sqlite3",
        "relations.jsonl",
        "runs.jsonl",
        "search-events.jsonl",
        "sources.jsonl",
        "urls.jsonl",
        "evidence-sets.jsonl",
        "iowa-objects.jsonl",
        "urlquery-receipts.jsonl",
    }
    present = {path.name for path in (ROOT / "data").iterdir() if path.is_file()}
    unexpected = sorted(present - allowed_data)
    if unexpected:
        raise ValidationError(f"unexpected files in data/: {unexpected}")
    for path in ROOT.rglob("*.jsonl"):
        if path.stat().st_size > 5_000_000:
            raise ValidationError(f"oversized JSONL file: {path.relative_to(ROOT)}")
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if len(line.encode("utf-8")) > 20_000:
                raise ValidationError(f"{path.relative_to(ROOT)}:{line_number}: record exceeds 20 KB")


def validate_references(files: dict[str, list[dict]]) -> None:
    ids: dict[str, set[str]] = {}
    for filename, rows in files.items():
        record_ids = [row["id"] for row in rows]
        if len(record_ids) != len(set(record_ids)):
            raise ValidationError(f"{filename}: duplicate stable ID")
        ids[filename] = set(record_ids)

    seen_source_tuples: set[tuple[str | None, str]] = set()
    known_exact_urls = {row["url"] for row in files["urls.jsonl"]}
    for source in files["sources.jsonl"]:
        url = canonical_url(source["source_url"]) if source["source_url"] else None
        key = (url, source["source_revision"])
        if key in seen_source_tuples:
            raise ValidationError(f"{source['id']}: duplicate canonical source tuple {key}")
        seen_source_tuples.add(key)
        if source["source_url"] and source["source_url"] not in known_exact_urls:
            raise ValidationError(f"{source['id']}: source URL missing from urls.jsonl")

    for relation in files["relations.jsonl"]:
        checks = [
            ("source_id", "sources.jsonl"),
            ("claim_id", "claims.jsonl"),
            ("entity_id", "entities.jsonl"),
        ]
        for field, filename in checks:
            if relation[field] not in ids[filename]:
                raise ValidationError(f"{relation['id']}: unknown {field} {relation[field]!r}")

    relation_tuples = [
        (row["source_id"], row["claim_id"], row["entity_id"], row["relation_type"], row["support_type"])
        for row in files["relations.jsonl"]
    ]
    if len(relation_tuples) != len(set(relation_tuples)):
        raise ValidationError("relations.jsonl: duplicate evidence relation tuple")

    for event in files["search-events.jsonl"]:
        if event["run_id"] not in ids["runs.jsonl"]:
            raise ValidationError(f"{event['id']}: unknown run_id {event['run_id']!r}")

    for evidence_set in files["evidence-sets.jsonl"]:
        if evidence_set["run_id"] not in ids["runs.jsonl"]:
            raise ValidationError(f"{evidence_set['id']}: unknown run_id {evidence_set['run_id']!r}")
        parent = evidence_set["parent_set_id"]
        if parent is not None and parent not in ids["evidence-sets.jsonl"]:
            raise ValidationError(f"{evidence_set['id']}: unknown parent_set_id {parent!r}")
        for url_id in evidence_set["representative_url_ids"]:
            if url_id not in ids["urls.jsonl"]:
                raise ValidationError(f"{evidence_set['id']}: unknown representative URL {url_id!r}")
        for claim_id in evidence_set["claim_ids"]:
            if claim_id not in ids["claims.jsonl"]:
                raise ValidationError(f"{evidence_set['id']}: unknown claim ID {claim_id!r}")

    for filename in ("iowa-objects.jsonl", "urlquery-receipts.jsonl"):
        for row in files[filename]:
            if row["url_id"] not in ids["urls.jsonl"]:
                raise ValidationError(f"{row['id']}: unknown url_id {row['url_id']!r}")


def partition_map(row: dict) -> dict[str, int]:
    names = [item["name"] for item in row["partitions"]]
    if len(names) != len(set(names)):
        raise ValidationError(f"{row['id']}: duplicate partition name")
    return {item["name"]: item["count"] for item in row["partitions"]}


def validate_v5_collections(files: dict[str, list[dict]]) -> None:
    urls = {row["id"]: row for row in files["urls.jsonl"]}
    sets = {row["id"]: row for row in files["evidence-sets.jsonl"]}

    for row in sets.values():
        if row["member_count"] != row["published_url_count"] + row["withheld_count"]:
            raise ValidationError(f"{row['id']}: member count does not reconcile")
        if sum(partition_map(row).values()) != row["member_count"]:
            raise ValidationError(f"{row['id']}: partitions do not sum to member_count")

    expected_sets = {
        "set-v5-iowa-objects",
        "set-v5-urlquery-total",
        "set-v5-urlquery-safe",
        "set-v5-urlquery-withheld",
    }
    if set(sets) != expected_sets:
        raise ValidationError("evidence-sets.jsonl: unexpected V5 set inventory")
    expected_set_contracts = {
        "set-v5-iowa-objects": ("run-fanout-search-v5", ("clm-linuxiarz-iowa-family", "clm-linuxiarz-iowa-q4-q5"), "published_inventory", "iowa_objects"),
        "set-v5-urlquery-total": ("run-fanout-search-v5", ("clm-urlquery-same-submitter",), "aggregate", "aggregate"),
        "set-v5-urlquery-safe": ("run-fanout-search-v5", ("clm-urlquery-same-submitter", "clm-urlquery-harness-telemetry", "clm-urlquery-contentdm-prewiki"), "published_inventory", "urlquery_receipts"),
        "set-v5-urlquery-withheld": ("run-fanout-search-v5", ("clm-urlquery-same-submitter",), "aggregate_only", "aggregate"),
    }
    for set_id, expected in expected_set_contracts.items():
        actual = (sets[set_id]["run_id"], tuple(sets[set_id]["claim_ids"]), sets[set_id]["set_type"], sets[set_id]["member_collection"])
        if actual != expected:
            raise ValidationError(f"{set_id}: run/claim/type/collection contract changed")

    iowa_set = sets["set-v5-iowa-objects"]
    if (iowa_set["member_count"], iowa_set["published_url_count"], iowa_set["withheld_count"]) != (120, 120, 0):
        raise ValidationError("set-v5-iowa-objects: expected 120 published objects")
    if partition_map(iowa_set) != {
        "iowa-collab": 86,
        "iowa-post-final": 17,
        "iowa-cache": 13,
        "iowa-q5": 4,
    }:
        raise ValidationError("set-v5-iowa-objects: title-family counts changed")
    if (
        iowa_set["distinct_body_count"],
        iowa_set["epoch_count_reported"],
        iowa_set["epoch_count_receipt_verified"],
        iowa_set["epoch_prefix_rows"],
    ) != (110, 100, 98, 99):
        raise ValidationError("set-v5-iowa-objects: body or epoch audit counts changed")

    total_set = sets["set-v5-urlquery-total"]
    safe_set = sets["set-v5-urlquery-safe"]
    withheld_set = sets["set-v5-urlquery-withheld"]
    if (total_set["member_count"], total_set["published_url_count"], total_set["withheld_count"]) != (1609, 1496, 113):
        raise ValidationError("set-v5-urlquery-total: expected 1,609 = 1,496 + 113")
    if partition_map(total_set) != {"previously-verified": 39, "newly-located": 1570}:
        raise ValidationError("set-v5-urlquery-total: prior/new counts changed")
    if partition_map(safe_set) != {
        "known-v5": 39,
        "direct-source": 851,
        "datausa": 86,
        "vizhub-extension": 203,
        "contentdm-wrapper": 2,
        "http-traffic-extension": 315,
    }:
        raise ValidationError("set-v5-urlquery-safe: lane counts changed")
    if (safe_set["member_count"], safe_set["published_url_count"], safe_set["withheld_count"]) != (1496, 1496, 0):
        raise ValidationError("set-v5-urlquery-safe: expected 1,496 public receipts")
    if (withheld_set["member_count"], withheld_set["published_url_count"], withheld_set["withheld_count"]) != (113, 0, 113):
        raise ValidationError("set-v5-urlquery-withheld: expected aggregate-only 113")
    if partition_map(withheld_set) != {"direct-source": 7, "http-traffic-extension": 106}:
        raise ValidationError("set-v5-urlquery-withheld: lane counts changed")
    if safe_set["manifest_sha256"] != "94c3ea835ce5343e6aea6c0e87af32d7f3de72a7625f5d6341fbc8a3e170fe17":
        raise ValidationError("set-v5-urlquery-safe: safe manifest hash changed")
    if withheld_set["manifest_sha256"] != "802d6e870be34da7ed8ac87c2ee3254cb9dace12f0bc09bcbcc44bd7afbaa048":
        raise ValidationError("set-v5-urlquery-withheld: withheld manifest hash changed")
    if total_set["manifest_sha256"] != "033f0cbfad730cd31099385172e233eb716d1a731122ce69daa0c61c704c42ee":
        raise ValidationError("set-v5-urlquery-total: all-ID manifest hash changed")
    if iowa_set["manifest_sha256"] != "215ba90016a40abf96f568997901130fa85fc28bf33352b79da1702f717fd4af":
        raise ValidationError("set-v5-iowa-objects: URL-set manifest hash changed")
    if total_set["parent_set_id"] is not None or iowa_set["parent_set_id"] is not None:
        raise ValidationError("V5 top-level evidence set has an unexpected parent")
    if safe_set["parent_set_id"] != total_set["id"] or withheld_set["parent_set_id"] != total_set["id"]:
        raise ValidationError("URLQuery child set has an unexpected parent")
    if withheld_set["representative_url_ids"]:
        raise ValidationError("set-v5-urlquery-withheld: aggregate-only set cannot have representatives")
    expected_member_hashes = {
        "set-v5-iowa-objects": "732239cbf5ed3b790a33a295ab6a1c4fb4c6badac094d01208dfd597b327dfe7",
        "set-v5-urlquery-total": "033f0cbfad730cd31099385172e233eb716d1a731122ce69daa0c61c704c42ee",
        "set-v5-urlquery-safe": "343e7e431e82bfb418a0aa86aa45fcf5ab9b363c8d4dc432be6ed73e1c110a5e",
        "set-v5-urlquery-withheld": "e4a4a7e79c35b81b5676d56668fe1dfebf81c5a7d329062b576a261d0d5257ae",
    }
    for set_id, expected_hash in expected_member_hashes.items():
        if sets[set_id]["member_ids_sha256"] != expected_hash:
            raise ValidationError(f"{set_id}: member-ID hash changed")
    withheld_serialised = json.dumps(withheld_set, sort_keys=True)
    if re.search(r"https?://|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", withheld_serialised):
        raise ValidationError("set-v5-urlquery-withheld: aggregate-only record exposes a locator or receipt ID")

    iowa_rows = files["iowa-objects.jsonl"]
    if len(iowa_rows) != 120:
        raise ValidationError("iowa-objects.jsonl: expected 120 rows")
    if len({row["url_id"] for row in iowa_rows}) != 120:
        raise ValidationError("iowa-objects.jsonl: duplicate URL membership")
    for row in iowa_rows:
        if row["id"] != f"iowa-{row['object_key']}":
            raise ValidationError(f"{row['id']}: object key does not match ID")
        match = LINUXIARZ_IOWA_RE.fullmatch(urls[row["url_id"]]["url"])
        if not match or match.group("object") != row["object_key"]:
            raise ValidationError(f"{row['id']}: malformed or mismatched Linuxiarz URL")
        if row["author_label_authenticated"] is not False:
            raise ValidationError(f"{row['id']}: displayed author label must remain unauthenticated")
        expected_strong = row["object_key"] in STRONG_IOWA_OBJECTS
        if row["strong_q4_q5_sequence"] is not expected_strong:
            raise ValidationError(f"{row['id']}: strong-sequence membership changed")
        if expected_strong:
            expected_order = STRONG_IOWA_SEQUENCE.index(row["object_key"]) + 1
            if row["sequence_order"] != expected_order or row["sequence_time_utc"] is None:
                raise ValidationError(f"{row['id']}: sequence order or self-reported time changed")
        elif row["sequence_order"] is not None or row["sequence_time_utc"] is not None:
            raise ValidationError(f"{row['id']}: non-sequence object has sequence metadata")
        url_row = urls[row["url_id"]]
        if url_row["safe_to_open"] != "caution" or url_row["risk_tags"] != ["external_logging"]:
            raise ValidationError(f"{row['id']}: Linuxiarz URL opening guidance changed")
    if len({row["body_group_id"] for row in iowa_rows}) != 110:
        raise ValidationError("iowa-objects.jsonl: expected 110 body groups")
    if len({row["displayed_author_label"] for row in iowa_rows}) != 69:
        raise ValidationError("iowa-objects.jsonl: expected 69 displayed author labels")
    epoch_states = defaultdict(int)
    family_counts = defaultdict(int)
    for row in iowa_rows:
        epoch_states[row["embedded_epoch_state"]] += 1
        family_counts[row["title_family"]] += 1
    if dict(epoch_states) != {"standalone-verified": 98, "malformed-prefix": 1, "not-observed": 21}:
        raise ValidationError("iowa-objects.jsonl: embedded epoch states changed")
    if dict(family_counts) != partition_map(iowa_set):
        raise ValidationError("iowa-objects.jsonl: title families do not match evidence set")
    provider_dated = {row["object_key"] for row in iowa_rows if row["provider_time_basis"] == "rss-provider-dated"}
    if provider_dated != RSS_DATED_IOWA_OBJECTS:
        raise ValidationError("iowa-objects.jsonl: provider-dated RSS child set changed")
    iowa_member_hash = hashlib.sha256(
        ("\n".join(sorted(row["object_key"] for row in iowa_rows)) + "\n").encode("utf-8")
    ).hexdigest()
    if iowa_member_hash != iowa_set["member_ids_sha256"]:
        raise ValidationError("iowa-objects.jsonl: member-ID hash does not match evidence set")
    strong_url_ids = {row["url_id"] for row in iowa_rows if row["strong_q4_q5_sequence"]}
    if set(iowa_set["representative_url_ids"]) != strong_url_ids:
        raise ValidationError("set-v5-iowa-objects: representatives do not match the eight-object sequence")

    receipt_rows = files["urlquery-receipts.jsonl"]
    if len(receipt_rows) != 1496:
        raise ValidationError("urlquery-receipts.jsonl: expected 1,496 rows")
    if len({row["url_id"] for row in receipt_rows}) != 1496:
        raise ValidationError("urlquery-receipts.jsonl: duplicate URL membership")
    lane_counts = defaultdict(int)
    scope_counts = defaultdict(int)
    seen_scope_ids: dict[str, set[str]] = defaultdict(set)
    for row in receipt_rows:
        uuid = row["id"].removeprefix("uqr-")
        match = URLQUERY_REPORT_RE.fullmatch(urls[row["url_id"]]["url"])
        if not match or match.group("uuid") != uuid:
            raise ValidationError(f"{row['id']}: malformed or mismatched URLQuery report URL")
        if row["raw_submitted_path_published"] is not False:
            raise ValidationError(f"{row['id']}: raw submitted path must remain unpublished")
        url_row = urls[row["url_id"]]
        if url_row["safe_to_open"] != "caution" or url_row["risk_tags"] != ["external_logging"]:
            raise ValidationError(f"{row['id']}: URLQuery opening guidance changed")
        lane_counts[row["acquisition_lane"]] += 1
        scope_counts[row["evidence_scope"]] += 1
        seen_scope_ids[row["evidence_scope"]].add(uuid)
    if dict(lane_counts) != partition_map(safe_set):
        raise ValidationError("urlquery-receipts.jsonl: lanes do not match evidence set")
    for scope, expected_ids in URLQUERY_REPRESENTATIVE_SCOPES.items():
        if seen_scope_ids[scope] != expected_ids:
            raise ValidationError(f"urlquery-receipts.jsonl: {scope} representative set changed")
    if scope_counts["unclassified-same-submitter-receipt"] != 1476:
        raise ValidationError("urlquery-receipts.jsonl: expected 1,476 conservatively unclassified receipts")
    receipt_member_hash = hashlib.sha256(
        ("\n".join(sorted(row["id"].removeprefix("uqr-") for row in receipt_rows)) + "\n").encode("utf-8")
    ).hexdigest()
    if receipt_member_hash != safe_set["member_ids_sha256"]:
        raise ValidationError("urlquery-receipts.jsonl: member-ID hash does not match safe evidence set")
    representative_url_ids = {
        row["url_id"] for row in receipt_rows if row["evidence_scope"] != "unclassified-same-submitter-receipt"
    }
    if set(safe_set["representative_url_ids"]) != representative_url_ids:
        raise ValidationError("set-v5-urlquery-safe: representatives do not match classified receipt rows")
    if set(total_set["representative_url_ids"]) != representative_url_ids:
        raise ValidationError("set-v5-urlquery-total: representatives do not match classified receipt rows")

    tableau_rows = [row for row in files["urls.jsonl"] if "V5 suspect Tableau query residue" in row["labels"]]
    if len(tableau_rows) != 7 or len({row["url"] for row in tableau_rows}) != 7:
        raise ValidationError("urls.jsonl: expected seven distinct Tableau query residues")
    for row in tableau_rows:
        if row["canonical_host"] != "public.tableau.com":
            raise ValidationError(f"{row['id']}: Tableau residue has unexpected host")
        if row["safe_to_open"] != "caution" or row["risk_tags"] != ["external_logging"]:
            raise ValidationError(f"{row['id']}: Tableau residue opening guidance changed")
    extra_paste_urls = {f"https://paste.linuxiarz.pl/view/{object_key}" for object_key in EXTRA_V5_PASTE_OBJECTS}
    actual_extra_pastes = {
        row["url"] for row in files["urls.jsonl"]
        if row["url"] in extra_paste_urls and "fanout-search-v5" in row["discovered_in"]
    }
    if actual_extra_pastes != extra_paste_urls:
        raise ValidationError("urls.jsonl: six V5 paste-chain/context links are incomplete")


def validate_v5_report(files: dict[str, list[dict]]) -> None:
    report = (ROOT / "reports" / "v5.md").read_text(encoding="utf-8")
    urls = {row["id"]: row["url"] for row in files["urls.jsonl"]}
    required_ids = set()
    for evidence_set in files["evidence-sets.jsonl"]:
        required_ids.update(evidence_set["representative_url_ids"])
    required_ids.update(
        row["id"] for row in files["urls.jsonl"] if "V5 suspect Tableau query residue" in row["labels"]
    )
    for url_id in required_ids:
        if report.count(code_span(urls[url_id])) != 1:
            raise ValidationError(f"reports/v5.md: expected one exact representative entry for {url_id}")
    required_text = [
        "120 exact objects and 110 distinct body groups",
        "reported 100 epoch-bearing objects",
        "verified 98 standalone values and 99 rows",
        "1,609 unique receipts: 1,496 safe projected records and 113 aggregate-only exclusions",
        "The remaining 1,476 stay `unclassified-same-submitter-receipt`",
        "7 direct-source and 106 HTTP-traffic receipts",
        "The routes are not separate stored objects or proven actions.",
        "Neither is listed as agent-used infrastructure.",
    ]
    for value in required_text:
        if value not in report:
            raise ValidationError(f"reports/v5.md: missing generated statement {value!r}")


def validate_generated_database(files: dict[str, list[dict]], database_path: Path = DATABASE_PATH) -> None:
    try:
        connection = sqlite3.connect(f"file:{database_path}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        raise ValidationError(f"data/evidence.sqlite3: cannot open generated database: {exc}") from exc
    try:
        if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise ValidationError("data/evidence.sqlite3: integrity check failed")
        if connection.execute("PRAGMA foreign_key_check").fetchall():
            raise ValidationError("data/evidence.sqlite3: foreign key check failed")

        expected_iowa = {
            (
                row["id"], row["url_id"], row["object_key"], row["exact_title"], row["title_family"],
                row["body_group_id"], row["embedded_epoch_state"], row["displayed_author_label"],
                int(row["author_label_authenticated"]), row["novelty"], int(row["strong_q4_q5_sequence"]),
                row["sequence_order"], row["sequence_time_utc"], row["provider_time_basis"], row["notes"],
            )
            for row in files["iowa-objects.jsonl"]
        }
        actual_iowa = set(connection.execute("SELECT * FROM iowa_objects"))
        if actual_iowa != expected_iowa:
            raise ValidationError("data/evidence.sqlite3: iowa_objects differs from canonical JSONL")

        expected_receipts = {
            (
                row["id"], row["url_id"], row["observed_at"], row["acquisition_lane"], row["submitted_host"],
                row["evidence_scope"], row["classification_basis"], int(row["raw_submitted_path_published"]),
                row["notes"],
            )
            for row in files["urlquery-receipts.jsonl"]
        }
        actual_receipts = set(connection.execute("SELECT * FROM urlquery_receipts"))
        if actual_receipts != expected_receipts:
            raise ValidationError("data/evidence.sqlite3: urlquery_receipts differs from canonical JSONL")

        expected_sets = {
            (
                row["id"], row["parent_set_id"], row["run_id"], json.dumps(row["claim_ids"], separators=(",", ":")), row["name"], row["set_type"],
                row["member_collection"], row["member_count"], row["published_url_count"], row["withheld_count"],
                row["manifest_sha256"], row["member_ids_sha256"], json.dumps(row["partitions"], separators=(",", ":")),
                row["distinct_body_count"], row["epoch_count_reported"], row["epoch_count_receipt_verified"],
                row["epoch_prefix_rows"], json.dumps(row["representative_url_ids"], separators=(",", ":")), row["notes"],
            )
            for row in files["evidence-sets.jsonl"]
        }
        actual_sets = set(connection.execute("SELECT * FROM evidence_sets"))
        if actual_sets != expected_sets:
            raise ValidationError("data/evidence.sqlite3: evidence_sets differs from canonical JSONL")
    except sqlite3.Error as exc:
        raise ValidationError(f"data/evidence.sqlite3: generated schema is missing or invalid: {exc}") from exc
    finally:
        connection.close()


def validate_readme_links() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", readme):
        if target.startswith(("http://", "https://", "#")):
            continue
        path_text = target.split("#", 1)[0]
        if not path_text:
            continue
        if not (ROOT / path_text).exists():
            raise ValidationError(f"README.md: linked path does not exist: {path_text}")


def validate_url_report(rows: list[dict], url_report: str) -> None:
    url_report_lines = url_report.splitlines()
    id_line_numbers: dict[str, list[int]] = defaultdict(list)
    for line_number, line in enumerate(url_report_lines):
        if match := re.fullmatch(r"  - ID `(url-[a-f0-9]{16})`;.*", line):
            id_line_numbers[match.group(1)].append(line_number)

    for row in rows:
        locations = id_line_numbers.get(row["id"], [])
        if len(locations) != 1:
            raise ValidationError(f"reports/links.md: expected one entry for {row['id']}, found {len(locations)}")
        entry_line = url_report_lines[locations[0] - 1] if locations[0] else ""
        if code_span(row["url"]) not in entry_line:
            raise ValidationError(f"reports/links.md: exact URL missing beside {row['id']}")
        markdown_targets = {f"]({row['url']})", f"](<{row['url']}>)", f"<{row['url']}>"}
        if row["safe_to_open"] != "yes" and any(target in entry_line for target in markdown_targets):
            raise ValidationError(f"reports/links.md: caution/no URL became clickable for {row['id']}")

    extra_ids = sorted(set(id_line_numbers) - {row["id"] for row in rows})
    if extra_ids:
        raise ValidationError(f"reports/links.md: entries without URL records: {', '.join(extra_ids)}")


def validate_generated_links(files: dict[str, list[dict]]) -> None:
    report = (ROOT / "reports" / "index.md").read_text(encoding="utf-8")
    url_report = (ROOT / "reports" / "links.md").read_text(encoding="utf-8")
    related_sources = {row["source_id"] for row in files["relations.jsonl"]}
    for source in files["sources.jsonl"]:
        url = source["source_url"]
        if not url or source["id"] not in related_sources:
            continue
        if url not in report:
            raise ValidationError(f"reports/index.md: exact citation missing for {source['id']}")
        markdown_targets = {f"]({url})", f"](<{url}>)", f"<{url}>"}
        if source["safe_to_open"] != "yes" and any(target in report for target in markdown_targets):
            raise ValidationError(f"reports/index.md: caution/no source became clickable for {source['id']}")

    validate_url_report(files["urls.jsonl"], url_report)


def main() -> int:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    files: dict[str, list[dict]] = {}
    try:
        for filename, definition in COLLECTIONS.items():
            path = ROOT / "data" / filename
            rows = load_jsonl(path)
            files[filename] = rows
            for index, row in enumerate(rows, start=1):
                validate_value(row, schema["$defs"][definition], f"data/{filename}:{index}")
        validate_references(files)
        validate_safety(files)
        validate_v5_collections(files)
        validate_repository_shape()
        validate_readme_links()
        validate_generated_links(files)
        validate_v5_report(files)
        validate_generated_database(files)
    except (OSError, KeyError, ValidationError) as exc:
        print(f"validation failed: {exc}", file=sys.stderr)
        return 1

    counts = ", ".join(f"{name}={len(rows)}" for name, rows in files.items())
    print(f"validation passed: {counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
