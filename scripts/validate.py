#!/usr/bin/env python3
"""Validate the canonical JSONL collections and repository safety invariants."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schema" / "collections.schema.json"
COLLECTIONS = {
    "entities.jsonl": "entity",
    "urls.jsonl": "url",
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
        validate_repository_shape()
        validate_readme_links()
        validate_generated_links(files)
    except (OSError, KeyError, ValidationError) as exc:
        print(f"validation failed: {exc}", file=sys.stderr)
        return 1

    counts = ", ".join(f"{name}={len(rows)}" for name, rows in files.items())
    print(f"validation passed: {counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
