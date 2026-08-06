# Contributing

Contributions should improve correctness, reproducibility, platform compatibility, or diagnostic quality.

## Before opening a pull request

1. Create a focused branch.
2. Keep changes minimal and backward-compatible unless the issue requires otherwise.
3. Do not add real VMess links, tokens, private subscriptions, UUIDs, or user-identifying logs.
4. Run:

```bash
python -m compileall -q main.py tests
python -m unittest discover -s tests -v
```

5. Explain the failure mode, proposed behavior, and test evidence in the pull request.

## Network observations

Network behavior is route- and time-dependent. A useful report includes the operator, access type, broad city/region, date and local time, IPv4/IPv6 status, Xray version, command options, and sanitized error stage. Do not generalize one observation into a permanent operator rule.
