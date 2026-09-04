# Contributing evidence

Contributions should make one bounded evidential change at a time: a new source, a corrected relationship, a stronger caveat or a reproducible search event.

## Before adding a record

1. Prefer a static `collusion.wiki` revision, public history or passive registry record.
2. Separate observed facts, self-reported claims and researcher inference.
3. State novelty against the original report and against this investigation.
4. Use `not_located`, not `absent`, unless the comparison set is demonstrably exhaustive.
5. Add every exact public URL once to `data/urls.jsonl`, including byte-distinct query, fragment and encoding variants when the difference is evidential.

Do not add raw revision bodies, private paths or crawl dumps. Public URLs may contain credential, token, counter, redirect, tunnel or transformer material, but those values must remain inside the exact URL field and carry the matching risk tags. Credential, token, mutation and server-side-fetch URLs use `safe_to_open: no`.

For bulk scanner evidence, publish reviewed passive report locators and the smallest useful metadata projection. Do not copy submitted paths, reflected payloads, cookies, challenge state, network identifiers or aggregate-only receipt IDs into the repository. Keep acquisition lanes separate from semantic evidence classifications.

## Workflow

Edit only the canonical JSONL collections, then run:

```sh
python3 scripts/generate.py
python3 scripts/validate.py
git diff --check
```

Review both generated indexes and the database diff. The generator must publish every URL while rendering `caution` and `no` values as non-autolinked code literals.

## Pull request checklist

- Every new relationship has a stable ID and valid source, claim and entity IDs.
- Source URL/revision tuples are not duplicated.
- Exact URL values and their digest-derived IDs are unique.
- Timestamps state their precision; unknown timestamps are `null`.
- Claim language does not attribute an actor, provider, successful external effect or evaluation outcome without authentication.
- Non-passive URLs have explicit risk tags and opening guidance.
- Validation and generation are deterministic and pass locally.

Do not copy token or credential values into prose, labels or notes; preserve them only when they are part of an exact public URL record.
