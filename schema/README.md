# Schema and data dictionary

The canonical dataset is split into normalised JSONL collections. Every line is one JSON object and every object has a stable, human-readable ID. The generated SQLite `evidence` view joins the fields most people need.

## Collections

| Collection | Purpose |
| --- | --- |
| `entities.jsonl` | Normalised target sites, services and providers. |
| `urls.jsonl` | Exact, deduplicated public URLs with discovery and opening metadata. |
| `evidence-sets.jsonl` | Reconciled V5 inventory totals, partitions, hashes and aggregate-only exclusions. |
| `iowa-objects.jsonl` | One structured row per Linuxiarz Iowa object, including title family, body group and attribution boundary. |
| `urlquery-receipts.jsonl` | Safe URLQuery report locators with a projected metadata subset and conservative evidence scope. |
| `sources.jsonl` | Deduplicated citations and source-safety metadata. |
| `claims.jsonl` | Bounded claims, novelty, verification and caveats. |
| `relations.jsonl` | One evidence item per source–claim–entity relationship. |
| `runs.jsonl` | Investigation scope and method. |
| `search-events.jsonl` | Bounded search outcomes, including explicit `not_located` results. |

The machine-readable contract is [`collections.schema.json`](collections.schema.json). Unknown properties fail validation.

## Source fields

| Field | Meaning |
| --- | --- |
| `id` | Stable source ID. |
| `source_url` | Public citation URL, or `null` when no exact citation was recovered. |
| `source_revision` | Public revision or object identifier. |
| `first_seen_at` | Earliest defensible source timestamp in RFC 3339 form, or `null`. |
| `first_seen_precision` | `second`, `minute`, `date`, `approximate` or `unknown`. |
| `canonical_host` | Host of the source citation. The target host is held by the related entity. |
| `evidence_type` | Static revision, history, registry metadata, public object, indexed record, corpus aggregate or research summary. |
| `publication_status` | Whether the citation is public, redacted, private or withheld. |
| `risk_tags` | Credential, signed-token, mutating-endpoint, server-side-fetch, internal-target or external-logging risk. `none` cannot be combined with another tag. |
| `safe_to_open` | `yes`, `caution` or `no`; this is opening guidance, not publication status. |
| `notes` | Source-specific context that does not reproduce raw payloads. |

## Exact URL fields

| Field | Meaning |
| --- | --- |
| `id` | `url-` plus the first 16 hexadecimal characters of SHA-256 over the exact URL string. |
| `url` | Exact HTTP(S) URL as recovered. Query order, encoding, doubled slashes and fragments are preserved. |
| `canonical_host` | Lower-case host used for grouping and queries; a terminal DNS dot is removed. |
| `labels` | Distinct human labels attached to the URL in the investigation notes. |
| `discovered_in` | Bounded investigation records in which the exact URL was retained. |
| `mention_count` | Number of retained occurrences across those records. |
| `risk_tags` | Credential, token, mutation, server-side-fetch, internal-target or external-logging metadata. |
| `safe_to_open` | Whether following the URL is passive (`yes`), should be treated cautiously, or may have effects (`no`). |
| `notes` | URL-specific provenance or opening context. |

## Claim fields

| Field | Meaning |
| --- | --- |
| `category` | Queryable topic slug. |
| `summary` | Narrow claim supported or qualified by related evidence. |
| `claim_class` | `observed_fact`, `self_reported_claim` or `researcher_inference`. |
| `relevance` | High, medium or low research relevance. |
| `attribution_boundary` | What the record cannot identify or authenticate. |
| `novelty_vs_original_report` | `known`, `absent`, `partly_known` or `not_assessed`. |
| `investigation_status` | Whether the item is known, a new record/relationship/namespace/candidate, deeper analysis or rejected. |
| `verification_state` | What source or relationship readback was completed. |
| `review_method` | How the claim was checked. |
| `caveat` | The main interpretation limit. |
| `notes` | Additional concise context. |

## V5 inventory fields

`evidence-sets.jsonl` records related claim IDs, set totals, published and withheld counts, reconciled partitions, manifest hashes, member-ID hashes and representative URL IDs. Published-ledger member hashes are recomputed during validation. The aggregate-only URLQuery row contains no receipt IDs or locators.

`iowa-objects.jsonl` links each exact object URL to its displayed title, title family, one of 110 body groups, receipt-audited embedded-epoch state and eight-object Q4/Q5 subset membership. The subset carries an explicit sequence order and self-reported UTC value; other rows use `null`. Displayed author strings are retained as public labels with `author_label_authenticated: false`; they are not identities.

`urlquery-receipts.jsonl` publishes only the safe report locator, receipt timestamp, acquisition lane, submitted host and evidence scope. Submitted paths, payloads, cookies, challenge material, exit nodes and raw receipt bodies are excluded. Acquisition lanes are collection provenance, not evidence classifications; unreviewed rows remain `unclassified-same-submitter-receipt`.

## Relation fields

Each relation is an evidence item with stable references to one source, one claim and one entity. `relation_type` is a lower-case descriptive slug. `support_type` is one of `supports`, `qualifies`, `contradicts`, `context` or `suspect`; `evidence_strength` is `high`, `medium` or `low`.

The target or canonical host requested for relationship queries comes from `relations.entity_id -> entities.canonical_host`. Source URLs and source revisions are deduplicated separately.

## Deduplication and generation

Validation rejects duplicate IDs and duplicate canonical `(source_url, source_revision)` tuples for evidence citations. The exact URL inventory instead rejects only identical strings: byte-distinct variants remain separate because their fragments, query ordering and encodings can carry evidence. URL IDs are recomputed during validation.

Member-ID hashes use the lexicographically sorted public member identifiers joined with `\n` and a final newline. For the Iowa set the identifiers are the eight-character object keys; for the safe URLQuery set they are receipt UUIDs. Manifest hashes identify the reviewed source manifests or externally retained aggregate manifests and are not substitutes for the recomputed member hash.

Run `python3 scripts/generate.py` after editing canonical JSONL. Commit the regenerated Markdown and SQLite views with the source change. `reports/links.md` must contain every exact URL; `caution` and `no` records appear as code literals rather than automatic links. The SQLite views `v5_inventory_summary`, `iowa_object_inventory` and `urlquery_receipt_inventory` expose the V5 ledgers without parsing JSONL.
