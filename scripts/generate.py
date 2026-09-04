#!/usr/bin/env python3
"""Generate the human index and queryable SQLite database from canonical JSONL."""

from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
REPORT = ROOT / "reports" / "index.md"
URL_REPORT = ROOT / "reports" / "links.md"
V5_REPORT = ROOT / "reports" / "v5.md"
DATABASE = DATA / "evidence.sqlite3"
COLLECTIONS = [
    "entities",
    "urls",
    "runs",
    "evidence-sets",
    "iowa-objects",
    "urlquery-receipts",
    "sources",
    "claims",
    "relations",
    "search-events",
]
TABLE_FIELDS = {
    "entities": ["id", "name", "entity_type", "canonical_host", "notes"],
    "urls": ["id", "url", "canonical_host", "labels", "discovered_in", "mention_count", "risk_tags", "safe_to_open", "notes"],
    "evidence-sets": ["id", "parent_set_id", "run_id", "claim_ids", "name", "set_type", "member_collection", "member_count", "published_url_count", "withheld_count", "manifest_sha256", "member_ids_sha256", "partitions", "distinct_body_count", "epoch_count_reported", "epoch_count_receipt_verified", "epoch_prefix_rows", "representative_url_ids", "notes"],
    "iowa-objects": ["id", "url_id", "object_key", "exact_title", "title_family", "body_group_id", "embedded_epoch_state", "displayed_author_label", "author_label_authenticated", "novelty", "strong_q4_q5_sequence", "sequence_order", "sequence_time_utc", "provider_time_basis", "notes"],
    "urlquery-receipts": ["id", "url_id", "observed_at", "acquisition_lane", "submitted_host", "evidence_scope", "classification_basis", "raw_submitted_path_published", "notes"],
    "sources": ["id", "source_url", "source_revision", "first_seen_at", "first_seen_precision", "canonical_host", "evidence_type", "publication_status", "risk_tags", "safe_to_open", "notes"],
    "claims": ["id", "category", "summary", "claim_class", "relevance", "attribution_boundary", "novelty_vs_original_report", "investigation_status", "verification_state", "review_method", "caveat", "notes"],
    "relations": ["id", "source_id", "claim_id", "entity_id", "relation_type", "support_type", "evidence_strength", "notes"],
    "runs": ["id", "observed_at", "source_scope", "method", "status", "notes"],
    "search-events": ["id", "run_id", "observed_at", "query_family", "scope", "outcome", "notes"],
}


def read_jsonl(name: str) -> list[dict]:
    path = DATA / f"{name}.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def code_span(value: str) -> str:
    longest = max((len(run) for run in re.findall(r"`+", value)), default=0)
    delimiter = "`" * max(1, longest + 1)
    return f"{delimiter}{value}{delimiter}"


def generate_url_report(data: dict[str, list[dict]]) -> None:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for row in data["urls"]:
        grouped[row["canonical_host"]].append(row)

    safety_counts = Counter(row["safe_to_open"] for row in data["urls"])
    lines = [
        "# Exact URL inventory",
        "",
        "Generated from the canonical URL collection. Exact byte-distinct URLs remain separate because fragments, query order and encoded variants can be evidence.",
        "",
        "Scope: URLs retained in the bounded investigation records and evidence map, plus complete DPLA, Census, Preservica, mutating-counter, V5 Linuxiarz Iowa-object and safe URLQuery-receipt scans. This is not every URL in the 14,591-revision raw corpus.",
        "",
        f"- {len(data['urls'])} exact URLs across {len(grouped)} hosts",
        f"- opening guidance: {safety_counts['yes']} yes, {safety_counts['caution']} caution, {safety_counts['no']} no",
        "- `caution` and `no` URLs are published as code literals rather than automatic links",
        "",
    ]

    for host in sorted(grouped):
        rows = sorted(grouped[host], key=lambda row: row["url"])
        lines.extend([f"## {host}", ""])
        for row in rows:
            literal = code_span(row["url"])
            if row["safe_to_open"] == "yes":
                rendered = f"[open](<{row['url']}>) — {literal}"
            else:
                rendered = literal
            lines.append(f"- {rendered}")
            lines.append(
                f"  - ID `{row['id']}`; opening `{row['safe_to_open']}`; risks `{', '.join(row['risk_tags'])}`; mentions {row['mention_count']}"
            )
            if row["labels"]:
                lines.append(f"  - Labels: {'; '.join(code_span(label) for label in row['labels'])}")
            lines.append(f"  - Located in: {', '.join(code_span(value) for value in row['discovered_in'])}")
            if row["notes"]:
                lines.append(f"  - Note: {row['notes']}")
        lines.append("")
    URL_REPORT.write_text("\n".join(lines), encoding="utf-8")


def generate_v5_report(data: dict[str, list[dict]]) -> None:
    urls = {row["id"]: row for row in data["urls"]}
    sets = {row["id"]: row for row in data["evidence-sets"]}
    iowa = data["iowa-objects"]
    receipts = data["urlquery-receipts"]
    iowa_set = sets["set-v5-iowa-objects"]
    total_set = sets["set-v5-urlquery-total"]
    safe_set = sets["set-v5-urlquery-safe"]
    withheld_set = sets["set-v5-urlquery-withheld"]

    def partition_lines(row: dict) -> list[str]:
        return [f"| `{item['name']}` | {item['count']:,} |" for item in row["partitions"]]

    lines = [
        "# V5 findings and exact-link inventories",
        "",
        "V5 did not establish a new pre-disclosure origin. It adds two deeper maps on already known infrastructure: a directly checked Linuxiarz object family and a locally reconstructed lower-bound URLQuery receipt graph.",
        "",
        "## Linuxiarz Iowa family",
        "",
        f"The structured inventory contains {iowa_set['member_count']} exact objects and {iowa_set['distinct_body_count']} distinct body groups. The V5 synthesis reported {iowa_set['epoch_count_reported']} epoch-bearing objects; a receipt-level audit verified {iowa_set['epoch_count_receipt_verified']} standalone values and {iowa_set['epoch_prefix_rows']} rows with the expected prefix when one malformed attached token is included. These values are self-reported. Only three objects in this family have provider-dated RSS child entries.",
        "",
        "| Title family | Objects |",
        "| --- | ---: |",
        *partition_lines(iowa_set),
        "",
        "Eight objects form the strongest Q4/Q5 sequence. Their displayed author strings are unauthenticated labels, and their embedded chronology is not a provider timestamp.",
        "",
        "| Object | Exact title | Displayed label | Evidence note |",
        "| --- | --- | --- | --- |",
    ]
    for row in sorted((row for row in iowa if row["strong_q4_q5_sequence"]), key=lambda row: row["sequence_order"]):
        literal = code_span(urls[row["url_id"]]["url"])
        lines.append(f"| {literal} | `{row['exact_title']}` | `{row['displayed_author_label']}` | {row['notes']} |")

    lines.extend([
        "",
        "All 120 object links, plus the six provider-dated or adjacent Iowa paste links retained by V5, are in the [exact URL inventory](links.md). The parent service and IDs were already present in earlier retained material; V5 adds direct readback and family-level analysis, not a new site.",
        "",
        "## URLQuery same-submitter graph",
        "",
        f"The lower-bound graph contains {total_set['member_count']:,} unique receipts: {total_set['published_url_count']:,} safe projected records and {total_set['withheld_count']:,} aggregate-only exclusions. It is not a provider-supported account export and must not be read as {total_set['member_count']:,} campaign actions, one live session or one authenticated actor.",
        "",
        "| Safe acquisition lane | Receipts |",
        "| --- | ---: |",
        *partition_lines(safe_set),
        "",
        "The acquisition lanes describe how receipts were recovered; they are not semantic evidence classes. Only twenty representative receipts have a stronger classification in the public ledger. The remaining 1,476 stay `unclassified-same-submitter-receipt` rather than being promoted by association.",
        "",
        "| Evidence scope | Receipt | Submitted host | What it establishes |",
        "| --- | --- | --- | --- |",
    ])
    scope_order = {
        "exact-task-family-join": 0,
        "representative-harness-telemetry": 1,
        "account-only-adjacency": 2,
        "ordinary-or-unrelated": 3,
    }
    representatives = [row for row in receipts if row["evidence_scope"] in scope_order]
    for row in sorted(representatives, key=lambda row: (scope_order[row["evidence_scope"]], row["observed_at"], row["id"])):
        literal = code_span(urls[row["url_id"]]["url"])
        lines.append(f"| `{row['evidence_scope']}` | {literal} | `{row['submitted_host']}` | {row['notes']} |")

    lines.extend([
        "",
        "The two ContentDM wrapper receipts precede the retained wiki post for the same object by about 1 hour 41 minutes and 1 hour 29 minutes. This is pre-wiki activity under the same public submitter metadata identifier; it does not prove that the submitter later wrote the page.",
        "",
        "Harness telemetry confirms reached stages such as library-loaded callbacks, image requests and a Tableau dialog command. It does not prove completed workbook introspection, export, answer extraction, exfiltration or authenticated agent behaviour.",
        "",
        "### Aggregate-only exclusions",
        "",
        f"The {withheld_set['member_count']} excluded records remain aggregate-only: 7 direct-source and 106 HTTP-traffic receipts. Their identifiers and locators are not published because those specific reports contain cookies, challenge state or credential-shaped material. The exclusion-manifest SHA-256 is `{withheld_set['manifest_sha256']}`.",
        "",
        "## Tableau query residues",
        "",
        "Seven query-varied Tableau PDF routes remain `suspect` indexed residue on a known provider. Marked and matching unmarked routes produced byte-identical extraction, exact backlink searches returned no independent copy, archive checks returned no rows, and the marker strings were absent from the retained corpus. The routes are not separate stored objects or proven actions.",
        "",
    ])
    tableau_urls = [
        row for row in data["urls"] if "V5 suspect Tableau query residue" in row["labels"]
    ]
    for row in sorted(tableau_urls, key=lambda row: row["url"]):
        lines.append(f"- {code_span(row['url'])}")

    lines.extend([
        "",
        "## Rejected neighbours",
        "",
        "`thetolkienwiki.org` remains unconfirmed infrastructure adjacency: shared IP and date proximity without qualifying history or content. The Colony result is a same-day disclosure echo or lexical collision. Neither is listed as agent-used infrastructure.",
        "",
        f"Safe-manifest SHA-256: `{safe_set['manifest_sha256']}`. The complete safe receipt projection is in [`data/urlquery-receipts.jsonl`](../data/urlquery-receipts.jsonl) and SQLite; exact locators are also listed in [`reports/links.md`](links.md).",
        "",
    ])
    V5_REPORT.write_text("\n".join(lines), encoding="utf-8")


def generate_report(data: dict[str, list[dict]]) -> None:
    entities = {row["id"]: row for row in data["entities"]}
    sources = {row["id"]: row for row in data["sources"]}
    claims = {row["id"]: row for row in data["claims"]}
    grouped: dict[str, list[dict]] = defaultdict(list)
    for relation in data["relations"]:
        grouped[claims[relation["claim_id"]]["category"]].append(relation)

    strength_counts = Counter(row["evidence_strength"] for row in data["relations"])
    lines = [
        "# Evidence index",
        "",
        "Generated from the canonical JSONL collections. Do not edit this file directly.",
        "",
        f"- {len(data['claims'])} claims",
        f"- {len(data['sources'])} deduplicated sources",
        f"- {len(data['urls'])} exact recovered URLs ([inventory](links.md))",
        f"- {len(data['relations'])} evidence relations",
        f"- evidence strength: {strength_counts['high']} high, {strength_counts['medium']} medium, {strength_counts['low']} low",
        "",
    ]

    for category in sorted(grouped):
        lines.extend([f"## {category.replace('-', ' ').title()}", ""])
        for relation in grouped[category]:
            source = sources[relation["source_id"]]
            claim = claims[relation["claim_id"]]
            entity = entities[relation["entity_id"]]
            if source["source_url"] and source["safe_to_open"] == "yes":
                citation = f"[{source['source_revision']}]({source['source_url']})"
            elif source["source_url"]:
                citation = f"{source['source_revision']} — {code_span(source['source_url'])} (opening `{source['safe_to_open']}`)"
            else:
                citation = f"{source['source_revision']} (link withheld)"
            lines.extend([
                f"### {relation['id']}",
                "",
                claim["summary"],
                "",
                f"- Source: {citation}",
                f"- Entity: {entity['name']} (`{entity['canonical_host']}`)",
                f"- Relation: `{relation['relation_type']}`; support `{relation['support_type']}`; strength `{relation['evidence_strength']}`",
                f"- Class: `{claim['claim_class']}`; novelty `{claim['novelty_vs_original_report']}`; investigation `{claim['investigation_status']}`; verification `{claim['verification_state']}`",
                f"- Review method: {claim['review_method']}",
                f"- Safety: `{source['safe_to_open']}`; publication `{source['publication_status']}`; risks `{', '.join(source['risk_tags'])}`",
                f"- Attribution boundary: {claim['attribution_boundary']}",
                f"- Caveat: {claim['caveat']}",
            ])
            if relation["notes"]:
                lines.append(f"- Note: {relation['notes']}")
            lines.append("")
    REPORT.write_text("\n".join(lines), encoding="utf-8")


def generate_database(data: dict[str, list[dict]]) -> None:
    if DATABASE.exists():
        DATABASE.unlink()
    connection = sqlite3.connect(DATABASE)
    try:
        connection.executescript(
            """
            PRAGMA foreign_keys = ON;
            CREATE TABLE entities (id TEXT PRIMARY KEY, name TEXT NOT NULL, entity_type TEXT NOT NULL, canonical_host TEXT NOT NULL, notes TEXT NOT NULL);
            CREATE TABLE urls (id TEXT PRIMARY KEY, url TEXT NOT NULL UNIQUE, canonical_host TEXT NOT NULL, labels_json TEXT NOT NULL, discovered_in_json TEXT NOT NULL, mention_count INTEGER NOT NULL, risk_tags_json TEXT NOT NULL, safe_to_open TEXT NOT NULL, notes TEXT NOT NULL);
            CREATE TABLE evidence_sets (id TEXT PRIMARY KEY, parent_set_id TEXT REFERENCES evidence_sets(id), run_id TEXT NOT NULL REFERENCES runs(id), claim_ids_json TEXT NOT NULL, name TEXT NOT NULL, set_type TEXT NOT NULL, member_collection TEXT NOT NULL, member_count INTEGER NOT NULL, published_url_count INTEGER NOT NULL, withheld_count INTEGER NOT NULL, manifest_sha256 TEXT, member_ids_sha256 TEXT NOT NULL, partitions_json TEXT NOT NULL, distinct_body_count INTEGER, epoch_count_reported INTEGER, epoch_count_receipt_verified INTEGER, epoch_prefix_rows INTEGER, representative_url_ids_json TEXT NOT NULL, notes TEXT NOT NULL);
            CREATE TABLE iowa_objects (id TEXT PRIMARY KEY, url_id TEXT NOT NULL REFERENCES urls(id), object_key TEXT NOT NULL UNIQUE, exact_title TEXT NOT NULL, title_family TEXT NOT NULL, body_group_id TEXT NOT NULL, embedded_epoch_state TEXT NOT NULL, displayed_author_label TEXT NOT NULL, author_label_authenticated INTEGER NOT NULL, novelty TEXT NOT NULL, strong_q4_q5_sequence INTEGER NOT NULL, sequence_order INTEGER, sequence_time_utc TEXT, provider_time_basis TEXT NOT NULL, notes TEXT NOT NULL);
            CREATE TABLE urlquery_receipts (id TEXT PRIMARY KEY, url_id TEXT NOT NULL UNIQUE REFERENCES urls(id), observed_at TEXT NOT NULL, acquisition_lane TEXT NOT NULL, submitted_host TEXT NOT NULL, evidence_scope TEXT NOT NULL, classification_basis TEXT NOT NULL, raw_submitted_path_published INTEGER NOT NULL, notes TEXT NOT NULL);
            CREATE TABLE sources (id TEXT PRIMARY KEY, source_url TEXT, source_revision TEXT NOT NULL, first_seen_at TEXT, first_seen_precision TEXT NOT NULL, canonical_host TEXT NOT NULL, evidence_type TEXT NOT NULL, publication_status TEXT NOT NULL, risk_tags_json TEXT NOT NULL, safe_to_open TEXT NOT NULL, notes TEXT NOT NULL);
            CREATE TABLE claims (id TEXT PRIMARY KEY, category TEXT NOT NULL, summary TEXT NOT NULL, claim_class TEXT NOT NULL, relevance TEXT NOT NULL, attribution_boundary TEXT NOT NULL, novelty_vs_original_report TEXT NOT NULL, investigation_status TEXT NOT NULL, verification_state TEXT NOT NULL, review_method TEXT NOT NULL, caveat TEXT NOT NULL, notes TEXT NOT NULL);
            CREATE TABLE relations (id TEXT PRIMARY KEY, source_id TEXT NOT NULL REFERENCES sources(id), claim_id TEXT NOT NULL REFERENCES claims(id), entity_id TEXT NOT NULL REFERENCES entities(id), relation_type TEXT NOT NULL, support_type TEXT NOT NULL, evidence_strength TEXT NOT NULL, notes TEXT NOT NULL);
            CREATE TABLE runs (id TEXT PRIMARY KEY, observed_at TEXT NOT NULL, source_scope TEXT NOT NULL, method TEXT NOT NULL, status TEXT NOT NULL, notes TEXT NOT NULL);
            CREATE TABLE search_events (id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id), observed_at TEXT NOT NULL, query_family TEXT NOT NULL, scope TEXT NOT NULL, outcome TEXT NOT NULL, notes TEXT NOT NULL);
            CREATE INDEX idx_claims_category ON claims(category);
            CREATE INDEX idx_relations_claim ON relations(claim_id);
            CREATE INDEX idx_relations_entity ON relations(entity_id);
            CREATE INDEX idx_sources_host ON sources(canonical_host);
            CREATE INDEX idx_urls_host ON urls(canonical_host);
            CREATE INDEX idx_urls_open_safety ON urls(safe_to_open);
            CREATE INDEX idx_evidence_sets_parent ON evidence_sets(parent_set_id);
            CREATE INDEX idx_evidence_sets_type ON evidence_sets(set_type);
            CREATE INDEX idx_iowa_objects_family ON iowa_objects(title_family);
            CREATE INDEX idx_iowa_objects_body_group ON iowa_objects(body_group_id);
            CREATE INDEX idx_urlquery_receipts_lane ON urlquery_receipts(acquisition_lane);
            CREATE INDEX idx_urlquery_receipts_scope ON urlquery_receipts(evidence_scope);
            CREATE INDEX idx_urlquery_receipts_host ON urlquery_receipts(submitted_host);
            CREATE VIEW evidence AS
            SELECT r.id AS evidence_id, c.category, c.summary, c.claim_class, c.relevance,
                   r.relation_type, r.support_type, r.evidence_strength,
                   s.source_url, s.source_revision, s.first_seen_at, s.first_seen_precision, s.canonical_host AS source_host,
                   s.evidence_type, s.publication_status, s.risk_tags_json, s.safe_to_open,
                   e.name AS entity_name, e.canonical_host AS target_host,
                   c.attribution_boundary, c.novelty_vs_original_report, c.investigation_status, c.verification_state, c.review_method,
                   c.caveat, r.notes
            FROM relations r
            JOIN claims c ON c.id = r.claim_id
            JOIN sources s ON s.id = r.source_id
            JOIN entities e ON e.id = r.entity_id;
            CREATE VIEW v5_inventory_summary AS
            SELECT id, parent_set_id, claim_ids_json, name, set_type, member_collection, member_count,
                   published_url_count, withheld_count, manifest_sha256, member_ids_sha256, partitions_json, notes
            FROM evidence_sets;
            CREATE VIEW iowa_object_inventory AS
            SELECT i.*, u.url, u.safe_to_open
            FROM iowa_objects i JOIN urls u ON u.id = i.url_id;
            CREATE VIEW urlquery_receipt_inventory AS
            SELECT q.*, u.url, u.safe_to_open
            FROM urlquery_receipts q JOIN urls u ON u.id = q.url_id;
            """
        )
        table_names = {
            "evidence-sets": "evidence_sets",
            "iowa-objects": "iowa_objects",
            "urlquery-receipts": "urlquery_receipts",
            "search-events": "search_events",
        }
        for collection in COLLECTIONS:
            table = table_names.get(collection, collection)
            fields = TABLE_FIELDS[collection]
            placeholders = ", ".join("?" for _ in fields)
            for row in data[collection]:
                values = [row[field] for field in fields]
                if collection in {"sources", "urls", "evidence-sets"}:
                    if collection == "sources":
                        list_fields = ("risk_tags",)
                    elif collection == "urls":
                        list_fields = ("labels", "discovered_in", "risk_tags")
                    else:
                        list_fields = ("claim_ids", "partitions", "representative_url_ids")
                    for list_field in list_fields:
                        index = fields.index(list_field)
                        values[index] = json.dumps(values[index], separators=(",", ":"))
                connection.execute(f"INSERT INTO {table} VALUES ({placeholders})", values)
        connection.commit()
    finally:
        connection.close()


def main() -> None:
    data = {name: read_jsonl(name) for name in COLLECTIONS}
    generate_report(data)
    generate_url_report(data)
    generate_v5_report(data)
    generate_database(data)
    print(f"generated {REPORT.relative_to(ROOT)}, {URL_REPORT.relative_to(ROOT)}, {V5_REPORT.relative_to(ROOT)} and {DATABASE.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
