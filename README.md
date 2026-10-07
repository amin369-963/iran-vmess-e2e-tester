# Proxy End-to-End Tester (VMess / VLESS / Trojan / Shadowsocks)

[![Tests](https://github.com/amin369-963/iran-vmess-e2e-tester/actions/workflows/tests.yml/badge.svg)](https://github.com/amin369-963/iran-vmess-e2e-tester/actions/workflows/tests.yml)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A Python 3.9+ command-line tool that validates `vmess://`, `vless://` (including REALITY), `trojan://` and `ss://` configurations with a real isolated **Xray Core** process and sends HTTPS requests through the resulting SOCKS5 tunnel.

An open TCP port, a successful TLS handshake, or a responsive CDN is **not** treated as proof that a configuration works.

Use `--protocol` (repeatable) to test only some protocols, e.g. `--protocol vless --protocol trojan`. Shadowsocks links that require a plugin are reported as parse failures.

Press **Ctrl+C** at any time: running Xray processes are stopped and the results collected so far are saved (the report is marked as interrupted).

`xray.exe` is found automatically when placed next to `main.py` (or in an `Xray` sub-folder); otherwise use `--xray` or `XRAY_PATH`.

The project began with Iranian mobile and fixed operators, but the measurement workflow is usable on restricted or unstable networks in other countries. Profiles only tune timeouts and concurrency; they are not bypass guarantees.

## Requirements

- Windows, Linux, or macOS
- Python 3.9 or newer
- Xray Core executable

```powershell
python -m pip install -r requirements.txt
```

Verify Xray:

```powershell
& "D:\v2ray\pythonProject\Xray\xray.exe" version
```

## Recommended comparison workflow

To compare the same configurations on several internet connections, keep the seed file unchanged and set a different `--network-name` for each run.

### MCI

```powershell
python main.py `
  --network-name "MCI-Tehran" `
  --profile mci `
  --xray "D:\v2ray\pythonProject\Xray\xray.exe" `
  --seed-file "configs_fixed.txt" `
  --no-default-sources
```

### Irancell

```powershell
python main.py `
  --network-name "Irancell-Tehran" `
  --profile irancell `
  --xray "D:\v2ray\pythonProject\Xray\xray.exe" `
  --seed-file "configs_fixed.txt" `
  --no-default-sources
```

### TCI or home broadband

```powershell
python main.py `
  --network-name "TCI-Home" `
  --profile tci `
  --xray "D:\v2ray\pythonProject\Xray\xray.exe" `
  --seed-file "configs_fixed.txt" `
  --no-default-sources
```

For a valid comparison, the `Input set SHA-256` value in all reports must be identical.

## Output files

Every run is stored separately and never overwrites an earlier run:

```text
results/
├── MCI-Tehran/
│   ├── 20260806_124200_accepted_links.txt
│   ├── 20260806_124200_report.txt
│   └── 20260806_124200_report.json
├── Irancell-Tehran/
│   └── ...
├── .test_history.lock
└── test_history.txt
```

- `*_accepted_links.txt`: accepted links only (all protocols), one raw link per line, ordered by score. Runs before v3.2.0 used `*_accepted_vmess.txt`.
- `*_report.txt`: UTF-8 with BOM, designed to open correctly in Windows Notepad.
- `*_report.json`: complete machine-readable technical report.
- `test_history.txt`: append-only summary of all runs and their input hashes.

CSV/Excel output has been removed. Use the text report for manual review and JSON for automated analysis.

To omit links from the readable report while preserving the separate accepted-links file:

```powershell
python main.py ... --redact-links-in-report
```

## Important CLI options

- `--network-name`: connection label used for the output folder.
- `--output-dir`: root output directory; default is `results`.
- `--seed-file`: local subscription or exported text.
- `--no-default-sources`: test only the supplied local data.
- `--sample`: randomly test at most N parsed configurations.
- `--topk`: export only the best K accepted links.
- `--test-url`: repeatable HTTPS endpoint used by the end-to-end probe.
- `--workers`: concurrent isolated HTTPS screening tests (default profile: 8).
- `--quality-workers`: concurrent full tests of screening survivors (default: 2).
- `--single-stage`: use the previous testing workflow for comparison.
- `--attempts`: HTTPS probes per configuration.
- `--redact-links-in-report`: hide accepted links in `report.txt`.

Use `python main.py --help` for the full list.

## Two-stage testing

Deep testing now uses two bounded worker pools. HTTPS screening checks one complete
cycle of all configured test URLs, without speed downloads. Any successful probe
forwards the configuration immediately to the full-test pool; the screening score
does not decide acceptance. Only final results are written to reports and SQLite,
so a configuration is recorded once per run. Full tests retain the configured
attempts, timeouts, minimum score, and quality checks.

```powershell
python main.py --workers 8 --quality-workers 2
```

Non-default profiles keep their existing screening-worker counts. Explicit
`--workers` overrides that count. `--no-deep-test` uses a single pool and keeps
its existing behavior. Ctrl+C stops both pools and saves finalized results;
survivors awaiting full testing count as unfinished, never accepted.

Reports include testing elapsed time, finalized configurations per minute, stage
counts, and summed worker execution times. The stages overlap, so worker-time
sums are not elapsed time and should not be added to estimate run duration.
Source collection time is excluded from the testing timer.

For comparison on the same frozen input file:

```powershell
python main.py --seed-file configs_fixed.txt --no-default-sources --network-name Before --single-stage
python main.py --seed-file configs_fixed.txt --no-default-sources --network-name After --workers 8 --quality-workers 2
```

Screening adds an extra Xray start and HTTPS cycle for survivors. If most
configurations work, the full-test pool can become the bottleneck and this mode
can be slower. Failed screening receives fewer repeated attempts than a full
test, so transient failures can reject a configuration that a later retry would
recover; use `--single-stage` for a more thorough comparison. Simultaneous speed
downloads share the same internet connection, including with screening traffic.

## Using the tester outside Iran

Choose settings according to the observed interference pattern rather than only the country name.

### Blocked GitHub or subscription sources

Use a local file:

```powershell
python main.py `
  --network-name "Local-ISP" `
  --xray "C:\Xray\xray.exe" `
  --seed-file "configs.txt" `
  --no-default-sources
```

`--source-proxy` affects source downloads only. It is not used for the VMess end-to-end probes.

### Blocked or throttled default test endpoints

Provide at least two small HTTPS endpoints appropriate for that network: one regional endpoint and one international endpoint.

```powershell
python main.py ... `
  --test-url "https://regional.example.net/generate_204" `
  --test-url "https://international.example.org/generate_204"
```

Replace placeholders with endpoints you control or trust. A local-only endpoint cannot prove international connectivity.

### Unstable or heavily inspected networks

Start with lower concurrency and more repeated attempts:

```powershell
python main.py ... `
  --workers 2 `
  --attempts 5 `
  --request-timeout 20 `
  --startup-timeout 12 `
  --min-score 55
```

For China, Russia, Iran, event-driven shutdowns, or other restrictive environments:

- test fixed and mobile access separately;
- record broad region, date/time, provider, Xray version, and IPv4/IPv6 status;
- use the same seed set and compare `input_set_sha256`;
- repeat the run at different times before making a claim;
- distinguish source-download failure from end-to-end VMess failure;
- do not assume one transport works universally across a country.

See [International Testing Guide](docs/INTERNATIONAL_TESTING.md).

## Failure stages

| Stage | Meaning | First check |
|---|---|---|
| `parse` | Invalid or unsupported link | Base64/JSON or URI fields, transport name, Shadowsocks cipher/plugin |
| `unreachable` | TCP pre-check could not connect to the server | Server down, port blocked, DNS; disable with `--no-tcp-precheck` |
| `validation` | Xray rejected the generated configuration | Xray version and transport compatibility |
| `startup` | Local Xray SOCKS inbound did not become ready | Xray log, server reachability, local firewall |
| `request` | Xray started but HTTPS probes failed or scored too low | Endpoint, route, DNS/TLS interference, expired account |
| `unexpected` | Worker or local execution failure | Full sanitized error and platform environment |

A failed request does not by itself prove censorship. Other causes include an expired account, wrong UUID, unavailable server, certificate error, routing failure, or unsuitable test endpoint.

## Privacy and security

Do not publish:

- active private configurations or UUIDs;
- access tokens or private subscription URLs;
- precise addresses, phone numbers, subscriber identifiers, or unredacted logs;
- generated JSON reports containing live server data.

`GITHUB_TOKEN` and `XRAY_PATH` can be supplied through environment variables. The GitHub token is sent only to GitHub-owned source hosts.

Review [SECURITY.md](SECURITY.md) before reporting a security issue.

## Community participation

Useful contributions include:

- reproducible network reports from new countries and providers;
- translations;
- parser and Xray-version compatibility fixes;
- improved privacy-safe summaries and error classification;
- Linux and macOS instructions;
- explicit IPv4/IPv6 test controls.

Use the **Global network report** issue form and remove all sensitive values before posting.

## فارسی

برای مقایسه چند نوع اینترنت، همیشه یک فایل ثابت مانند `configs_fixed.txt` را استفاده کنید و در هر اجرا فقط `--network-name` و پروفایل اینترنت را تغییر دهید. اگر مقدار `Input set SHA-256` در گزارش‌ها یکسان نباشد، مقایسه معتبر نیست.

خروجی CSV حذف شده و به‌جای آن گزارش متنی مناسب Notepad، گزارش JSON، فایل لینک‌های پذیرفته‌شده و تاریخچه کلی اجراها تولید می‌شود.

## License

MIT License. See [LICENSE](LICENSE).
