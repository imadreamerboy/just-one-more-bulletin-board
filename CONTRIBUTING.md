# Contributing evidence

Contributions should make one bounded evidential change at a time: a new source, a corrected relationship, a stronger caveat or a reproducible search event.

## Before adding a record

1. Prefer a static `collusion.wiki` revision, public history or passive registry record.
2. Separate observed facts, self-reported claims and researcher inference.
3. State novelty against the original report and against this investigation.
4. Use `not_located`, not `absent`, unless the comparison set is demonstrably exhaustive.
5. Withhold any link that exposes a credential, signed token, mutating endpoint, internal target or replayable write/fetch route.

Do not add raw revision bodies, credentials, tokens, exact IP addresses, private paths, crawl dumps, counter keys, write endpoints, short redirects, tunnel URLs or transformer/proxy targets. A source marked `safe_to_open: no` must have `source_url: null`.

## Workflow

Edit only the canonical JSONL collections, then run:

```sh
python3 scripts/generate.py
python3 scripts/validate.py
git diff --check
```

Review the generated index and database diff. The generator must never turn a `caution` or `no` source into a Markdown link.

## Pull request checklist

- Every new relationship has a stable ID and valid source, claim and entity IDs.
- Source URL/revision tuples are not duplicated.
- Timestamps state their precision; unknown timestamps are `null`.
- Claim language does not attribute an actor, provider, successful external effect or evaluation outcome without authentication.
- Unsafe targets are host-only, redacted or withheld.
- Validation and generation are deterministic and pass locally.

For a live credential or security-sensitive exposure, do not open a public issue containing the value. Use GitHub's private vulnerability-reporting route if it is available for the repository.
