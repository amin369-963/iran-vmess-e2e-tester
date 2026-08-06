# Iran VMess End-to-End Tester

A Python 3.9+ command-line tool that collects `vmess://` links and tests them through a real, isolated **Xray Core** process. It does not treat an open TCP/TLS port as proof that a VMess configuration works.

The project includes execution profiles for MCI, Irancell, TCI, fast screening, and offline/national-network conditions. Profiles only tune timeouts and concurrency; they do not claim that any Iranian operator uses one permanent filtering method.

## What it measures

- Xray configuration validity
- Real VMess authentication and transport startup
- HTTPS requests routed through a local SOCKS5 tunnel
- Success ratio, median end-to-end latency, and stability
- Separate parse, startup, validation, transport, and request failures
- Atomic TXT, JSON, and CSV output

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

Test only a local subscription or exported Telegram text:

```powershell
python main.py `
  --profile irancell `
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

## Outputs

- `v2ray_quality_vmess.txt`: accepted links only, sorted by score
- `v2ray_quality_report.json`: full metadata and probe details
- `v2ray_quality_report.csv`: analysis-friendly summary

## Optional environment variables

Copy `.env.example` values into your operating-system environment. The application does not load `.env` files automatically.

- `XRAY_PATH`: default path to Xray Core
- `GITHUB_TOKEN`: optional GitHub token used **only** for GitHub-hosted source requests

Never commit real tokens, private subscription URLs, UUIDs, or full output reports.

## Community reports

Use the GitHub issue forms to report:

- reproducible bugs
- feature proposals
- operator/network observations with sanitized logs

Do not post working private configurations, access tokens, subscriber identifiers, phone numbers, or precise addresses. Operator behavior can differ by city, access technology, ASN, time, SIM/account class, IPv4/IPv6 path, and current network controls.

## فارسی

این ابزار سالم‌بودن کانفیگ VMess را با اجرای واقعی Xray و عبور درخواست HTTPS از داخل تونل بررسی می‌کند. صرفاً بازبودن پورت یا موفقیت TLS به‌عنوان کانفیگ سالم پذیرفته نمی‌شود.

برای گزارش نتیجه اپراتورها از قالب **Operator / network report** در بخش Issues استفاده کنید و اطلاعات حساس یا کانفیگ خصوصی را منتشر نکنید.

## Security and scope

This repository is a diagnostic and research tool. It does not include, operate, or guarantee proxy servers. Results are time- and route-dependent. Review `SECURITY.md` before reporting a security issue.

## License

MIT License. See `LICENSE`.
