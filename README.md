# VMess End-to-End Tester

[![Tests](https://github.com/amin369-963/iran-vmess-e2e-tester/actions/workflows/tests.yml/badge.svg)](https://github.com/amin369-963/iran-vmess-e2e-tester/actions/workflows/tests.yml)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An Iran-focused but **globally usable** Python command-line tool that collects `vmess://` links and tests them through a real, isolated **Xray Core** process.

It does not treat an open TCP port, a successful TLS handshake, or a responsive CDN as proof that a VMess configuration works. A candidate is accepted only after real HTTPS requests pass through its local SOCKS5 tunnel.

The repository started with MCI, Irancell, and TCI use cases, but the same measurement method can be used on restricted networks in China, Russia, Central Asia, the Middle East, South Asia, and other environments where results differ by ISP, route, time, or filtering policy.

> Country and operator profiles are timeout/concurrency presets, not bypass guarantees. Internet interference commonly differs between networks inside the same country, so results must be measured from the actual target network.

## What it measures

- Xray configuration validity
- Real VMess authentication and transport startup
- HTTPS requests routed through a local SOCKS5 tunnel
- Success ratio, median end-to-end latency, and short-run stability
- Separate parse, validation, startup, and request failures
- Atomic TXT, JSON, and CSV output

## What it does not measure

- Resistance to active probing or long-term server discovery
- UDP/QUIC reliability
- VLESS, Trojan, Shadowsocks, WireGuard, or Hysteria protocols
- Whether a server remains usable after the test
- Legal or personal-security risk in the user's country

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

## Quick start

```powershell
python main.py `
  --profile mci `
  --xray "D:\v2ray\pythonProject\Xray\xray.exe" `
  --sample 20 `
  --topk 5 `
  --verbose
```

Test only a local subscription or exported text file:

```powershell
python main.py `
  --profile default `
  --xray "D:\v2ray\pythonProject\Xray\xray.exe" `
  --seed-file "configs.txt" `
  --no-default-sources `
  --topk 20
```

Offline/national-network mode intentionally ignores remote sources:

```powershell
python main.py `
  --profile national `
  --xray "D:\v2ray\pythonProject\Xray\xray.exe" `
  --seed-file "configs.txt"
```

## Using the tester outside Iran

The best settings depend on the **observed interference pattern**, not only the country name.

### 1. When GitHub or subscription sources are blocked

Use a locally saved and sanitized seed file instead of interpreting source-download failure as VMess failure:

```powershell
python main.py `
  --profile default `
  --xray "C:\Xray\xray.exe" `
  --seed-file "configs.txt" `
  --no-default-sources
```

Use `--source-proxy` only when you already have a trusted working proxy for downloading public source lists. It is not used for the end-to-end VMess probes.

### 2. When the default test endpoints are blocked or throttled

Supply two or more HTTPS endpoints that are appropriate for the target network:

- one reachable regional endpoint to establish a baseline;
- one international endpoint to test external routing;
- endpoints that return a small stable response and do not require login.

```powershell
python main.py `
  --xray "C:\Xray\xray.exe" `
  --seed-file "configs.txt" `
  --no-default-sources `
  --test-url "https://regional.example.net/generate_204" `
  --test-url "https://international.example.org/generate_204"
```

Replace the placeholder domains with endpoints you control or know are reachable. A local-only endpoint cannot prove international connectivity.

### 3. For unstable or heavily inspected networks

Start conservatively:

```powershell
python main.py `
  --profile default `
  --xray "C:\Xray\xray.exe" `
  --seed-file "configs.txt" `
  --no-default-sources `
  --workers 2 `
  --attempts 5 `
  --request-timeout 20 `
  --startup-timeout 12 `
  --min-score 55
```

Lower concurrency reduces local resource contention and makes rate-limiting artifacts less likely. More attempts help distinguish transient loss from repeatable failure.

## Country and filtering examples

These notes describe **measurement strategy**, not permanent country rules.

### China / Great Firewall environments

Published measurements have documented DNS injection, TLS/SNI interference, and newer QUIC filtering in China. Recommended testing workflow:

- use `--seed-file --no-default-sources` when public source hosts are unreliable;
- test with separate regional and international HTTPS endpoints;
- begin with `--workers 1` or `2`, `--attempts 5`, and longer timeouts;
- repeat the same sample on different access networks and at different times;
- compare multiple VMess transport families rather than assuming one transport is universally best.

Current Xray documentation recommends considering XHTTP instead of WebSocket or gRPC because those transports can have more recognizable characteristics or active-probing concerns. This program **tests the supplied configuration**; it does not rewrite a server or convert one transport into another.

### Russia / centralized DPI environments

Russia's TSPU infrastructure and protocol-targeted controls make route and provider comparisons important:

- test fixed broadband and mobile networks separately;
- record the provider, broad region, date/time, Xray version, and address family;
- run the same sanitized sample more than once rather than publishing one snapshot;
- compare failure stages and transport families, not just the accepted count;
- use local seed files if public repositories or subscription endpoints are blocked.

### Iran / operator-dependent and selective access

The `mci`, `irancell`, and `tci` profiles tune concurrency and timeouts only. For useful evidence:

- run each operator separately;
- separate mobile data, fixed broadband, fiber, and organizational access;
- record IPv4/IPv6 state and the approximate test time;
- use the `national` profile only with locally available seed data;
- do not describe one successful city/operator test as a nationwide result.

### Event-driven throttling, partial shutdowns, or whitelisting

For countries where access changes during elections, protests, exams, conflicts, or local shutdowns:

- capture a baseline before the event when possible;
- repeat the same command during and after the disruption;
- use several test endpoints to distinguish endpoint blocking from broader routing failure;
- preserve only sanitized JSON/CSV summaries;
- report complete loss of international routing separately from protocol-specific failure.

If no international route exists, increasing retries or timeouts cannot create one. The result should be reported as a network condition, not as proof that every VMess configuration is invalid.

See [International Testing Guide](docs/INTERNATIONAL_TESTING.md) for a filtering-pattern matrix, result interpretation, and reproducible reporting method.

## Interpreting failure stages

| Stage | Meaning | First check |
|---|---|---|
| `parse` | Invalid or unsupported VMess link | Base64/JSON fields and transport name |
| `validation` | Xray rejected the generated configuration | Xray version and transport compatibility |
| `startup` | Local Xray SOCKS inbound did not become ready | Xray log, server reachability, local firewall |
| `request` | Xray started but HTTPS probes failed or scored too low | test endpoint, route, DNS/TLS interference, transient loss |

A `request` failure is not automatically censorship. It may also indicate an expired account, incorrect UUID, unavailable server, certificate problem, routing failure, or an unsuitable test endpoint.

## Outputs

- `v2ray_quality_vmess.txt`: accepted links only, sorted by score
- `v2ray_quality_report.json`: full metadata and probe details
- `v2ray_quality_report.csv`: analysis-friendly summary

Do not commit generated reports containing live server addresses, UUIDs, private subscription data, or user-identifying metadata.

## Optional environment variables

The application does not load `.env` files automatically.

- `XRAY_PATH`: default path to Xray Core
- `GITHUB_TOKEN`: optional token used **only** for GitHub-hosted source requests

Never commit real tokens, private subscription URLs, UUIDs, or full output reports.

## Community participation

High-value contributions include:

- reproducible network reports from new countries and providers;
- translations of the README and testing guide;
- parser compatibility fixes for valid VMess exports;
- Xray version compatibility tests;
- improved error classification and privacy-safe reporting;
- documentation corrections backed by measurements or reliable sources.

Use the **Global network report** issue form. Report the country, provider, access type, broad region, date/time, Xray version, sanitized command, sample size, and summarized result. Never post a working private configuration or access credential.

Please star the repository only if it is useful, and open an issue when a result is reproducible. Evidence and sanitized logs are more valuable than general claims that a protocol "works" or "does not work" in an entire country.

## فارسی

این ابزار در ابتدا برای بررسی کانفیگ‌های VMess روی اپراتورهای ایران ساخته شده، اما روش آن برای شبکه‌های محدودشده در کشورهای دیگر نیز قابل استفاده است.

برای چین، روسیه یا سایر کشورها بهتر است:

- در صورت مسدودبودن منابع عمومی، از `--seed-file` و `--no-default-sources` استفاده شود؛
- آدرس‌های `--test-url` متناسب با همان شبکه انتخاب شوند؛
- تست با تعداد worker کم و چند تلاش تکراری اجرا شود؛
- نتایج شبکه‌های موبایل، ثابت، IPv4 و IPv6 جدا گزارش شوند؛
- اطلاعات حساس، UUID و کانفیگ فعال در Issue عمومی قرار نگیرد.

## Security, legality, and scope

This repository is a diagnostic and research tool. It does not provide, operate, or guarantee proxy servers. Network testing and circumvention tools may carry legal or personal-security risks in some jurisdictions. Users are responsible for understanding local law and their threat model.

Review [SECURITY.md](SECURITY.md) before reporting a security issue.

## References

- [OONI FAQ: censorship differs across networks and may involve DNS, TCP/IP blocking, or RST injection](https://ooni.org/support/faq/)
- [OONI: China blocking through DNS injection and TLS interference](https://ooni.org/post/2023-china-blocks-ooni/)
- [USENIX Security 2025: SNI-based QUIC censorship of the Great Firewall](https://www.usenix.org/conference/usenixsecurity25/presentation/zohaib)
- [Research on Russia's TSPU/DPI infrastructure](https://doi.org/10.5210/spir.v2024i0.15199)
- [Xray transport configuration and compatibility](https://xtls.github.io/en/config/transports/)
- [Xray WebSocket guidance](https://xtls.github.io/en/config/transports/websocket.html)
- [Xray gRPC guidance](https://xtls.github.io/en/config/transports/grpc.html)
- [OONI global research reports](https://ooni.org/reports/)

## License

MIT License. See [LICENSE](LICENSE).
