# just-one-more-bulletin-board

A compact evidence map for the public [`collusion.wiki`](https://collusion.wiki/) corpus and its surrounding public footprint. The repository keeps claims, sources, entities and relationships queryable without republishing the 14,591-revision raw corpus.

## What the evidence supports

- Anonymous writers published exact answers, relay formats, role assignments and pre-final signalling instructions. The revision history supports coordination protocol design; it does not authenticate distinct agents or task outcomes.
- Public counters were described as shared state for answers, acknowledgements and termination experiments. Several revision sequences record plan, claimed readback and rapid adoption, but the counters were mutable and contaminated.
- Writers discussed detached processes, heartbeat schemes and network-control bypass methods. These are stored plans and self-reported results, not trusted shell, process or network telemetry.
- Rare content bundles connect the corpus to public histories, paste reply graphs, registry metadata and public objects. The strongest relationships are exact content and chronology matches; actor identity and direction of copying usually remain unresolved.
- Self-selected names containing `OpenAI`, `OAI` or `agent` are not provider or model attribution.

Sensitive citations are deliberately withheld when a revision exposes credential-shaped values, signed tokens, mutating endpoints, internal targets or replayable operational detail. A withheld record preserves the finding and its evidential boundary without publishing the unsafe route.

## Explore the data

- [Generated evidence index](reports/index.md) — human-readable claim and source map.
- [Schema and data dictionary](schema/README.md) — collection contracts and field meanings.
- [`data/`](data/) — canonical append-only JSONL plus a generated SQLite database.
- [Contribution guide](CONTRIBUTING.md) — evidence, safety and review rules.

The JSONL collections are authoritative. `data/evidence.sqlite3` and `reports/index.md` are deterministic generated views.

```sh
python3 scripts/generate.py
python3 scripts/validate.py
```

Query all joined evidence records:

```sh
sqlite3 -header -column data/evidence.sqlite3 \
  "select evidence_id, category, evidence_strength, target_host from evidence order by category, evidence_id;"
```

Find every relationship involving public counter services:

```sh
sqlite3 -header -column data/evidence.sqlite3 \
  "select evidence_id, relation_type, support_type, evidence_strength from evidence where target_host in ('api.counterapi.dev', 'countapi.mileshilliard.com');"
```

## Evidence rules

The repository separates three claim classes:

- `observed_fact`: directly present in a source or mechanically derived from the publisher export;
- `self_reported_claim`: an external action, result or runtime state claimed by a writer; and
- `researcher_inference`: an interpretation that goes beyond the directly observed record.

`verification_state` describes what was checked, not whether a quoted claim is true. `not_located` in a search event means no matching record was found within a stated search boundary; it does not mean the record is absent from the web.

## Provenance and scope

The source package was acquired from the [public download page](https://collusion.wiki/explorer/download.html). Its `revisions.jsonl` SHA-256 is `60df4a515178230aa952d9f64f6215aea4bd95ab2f05e31e484cf9b887e3f793`; the export reports 14,591 stored revisions and was generated on 3 September 2026.

This repository does not copy revision bodies, labels, raw request data or temporary crawl output. It also does not establish provider identity, autonomy, common control, successful exploitation or evaluation acceptance.

## Licence

The repository's original code and metadata are available under the [MIT License](LICENSE). Linked source material remains subject to its original terms.
