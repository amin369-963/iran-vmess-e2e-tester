# Contributing

Contributions should improve correctness, reproducibility, platform compatibility, privacy, or diagnostic quality.

## High-value contributions

- Reproducible, sanitized network reports from new countries and providers
- README and guide translations that preserve technical meaning
- Parser compatibility fixes using redacted fixtures
- Xray release compatibility checks
- Better failure-stage classification
- Privacy-safe result aggregation
- IPv4/IPv6 comparison support
- Documentation corrections backed by measurements or reliable sources

Country-specific hard-coded profiles should not be added from one anecdotal result. A proposed profile needs repeated evidence from multiple networks or a clear operational purpose limited to timeout and concurrency tuning.

## Before opening a pull request

1. Create a focused branch.
2. Keep changes minimal and backward-compatible unless the issue requires otherwise.
3. Do not add real VMess links, tokens, private subscriptions, UUIDs, server credentials, or user-identifying logs.
4. Run:

```bash
python -m compileall -q main.py tests
python -m unittest discover -s tests -v
```

5. Explain the failure mode, proposed behavior, user impact, and test evidence.
6. Update documentation when CLI behavior or compatibility changes.

## Network observations

Network behavior is route- and time-dependent. Use the **Global network report** issue form.

A useful report includes:

- country and provider;
- broad region and access type;
- date/time and UTC offset;
- IPv4/IPv6 status;
- Python and Xray versions;
- sanitized command;
- sample size and transport distribution;
- accepted count, median latency, and failure-stage summary;
- whether the result was reproduced.

Do not generalize one observation into a permanent country or operator rule.

## Translation contributions

Translations are welcome for the README, international testing guide, and issue instructions.

- Preserve command-line flags exactly.
- Do not translate protocol, transport, environment-variable, or failure-stage identifiers.
- Keep safety warnings and privacy requirements intact.
- State the language and locale in the pull request.

## Research and citations

Country or filtering claims should cite measurement data, peer-reviewed research, official project documentation, or a clearly described reproducible experiment. Distinguish measured facts from hypotheses.

Useful starting points include OONI research and Explorer data, peer-reviewed censorship measurement papers, and official Xray documentation.
