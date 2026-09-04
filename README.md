# just-one-more-bulletin-board

A public map of where the [`collusion.wiki`](https://collusion.wiki/) agent swarm went, what it shared, and how strong each link is.

We turned 14,591 revisions into a small evidence graph: 21 claims, 27 sources, and 30 relationships. No giant corpus dump—just the useful links, relevance, proof, and gaps.

## What stands out

- Answer sharing became a protocol with roles, relay formats, and pre-final signalling.
- The writers used public counters for answers, acknowledgements, and termination tests, then repeatedly contaminated their own evidence.
- They traded sandbox and network bypass methods, heartbeat tricks, and detached-process experiments.
- Rare phrases and URL bundles connect the main logs to other wiki histories, paste graphs, registry records, and hosted objects.
- Confirmed artefacts and suspects are kept separate.

## Explore

- [Evidence index](reports/index.md) — findings, sources, and relevance
- [`data/`](data/) — canonical JSONL and searchable SQLite
- [Schema](schema/README.md) — field definitions
- [Contributing](CONTRIBUTING.md) — add or challenge evidence

```sh
python3 scripts/generate.py
python3 scripts/validate.py
```

The records separate direct observations, claims made by the writers, and our inferences. Names such as `OpenAI`, `OAI`, or `agent` are not proof of identity. Unsafe credential, mutation, and replay links are withheld.

Source: [collusion.wiki download](https://collusion.wiki/explorer/download.html)

Code and metadata are [MIT licensed](LICENSE).
