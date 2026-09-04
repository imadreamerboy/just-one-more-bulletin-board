# Schema and data dictionary

The canonical dataset is split into normalised JSONL collections. Every line is one JSON object and every object has a stable, human-readable ID. The generated SQLite `evidence` view joins the fields most people need.

## Collections

| Collection | Purpose |
| --- | --- |
| `entities.jsonl` | Normalised target sites, services and providers. |
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
| `source_url` | Safe read-only citation, or `null` when publication would expose unsafe material. |
| `source_revision` | Public revision/object identifier, or an explicit withheld locator. |
| `first_seen_at` | Earliest defensible source timestamp in RFC 3339 form, or `null`. |
| `first_seen_precision` | `second`, `minute`, `date`, `approximate` or `unknown`. |
| `canonical_host` | Host of the source citation. The target host is held by the related entity. |
| `evidence_type` | Static revision, history, registry metadata, public object, indexed record, corpus aggregate or research summary. |
| `publication_status` | Whether the citation is public, redacted, private or withheld in this release. |
| `risk_tags` | Credential, signed-token, mutating-endpoint, server-side-fetch, internal-target or external-logging risk. `none` cannot be combined with another tag. |
| `safe_to_open` | `yes`, `caution` or `no`. `no` requires a `null` URL. |
| `notes` | Source-specific context that does not reproduce raw payloads. |

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

## Relation fields

Each relation is an evidence item with stable references to one source, one claim and one entity. `relation_type` is a lower-case descriptive slug. `support_type` is one of `supports`, `qualifies`, `contradicts`, `context` or `suspect`; `evidence_strength` is `high`, `medium` or `low`.

The target or canonical host requested for relationship queries comes from `relations.entity_id -> entities.canonical_host`. Source URLs and source revisions are deduplicated separately.

## Deduplication and generation

Validation rejects duplicate IDs and duplicate canonical `(source_url, source_revision)` tuples. URL canonicalisation lower-cases the scheme and host, removes default ports and fragments, normalises an empty path, trims non-root trailing slashes and sorts query parameters. It does not follow redirects or decode paths.

Run `python3 scripts/generate.py` after editing canonical JSONL. Commit the regenerated Markdown and SQLite views with the source change.
