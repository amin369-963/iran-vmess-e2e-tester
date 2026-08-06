# International Testing Guide

This guide explains how to use the tester on restricted, unstable, or heavily inspected networks outside Iran.

The central rule is simple: **measure the actual network path instead of assigning one permanent behavior to an entire country.** Blocking can differ by ISP, ASN, city, access technology, account class, time, IPv4/IPv6 route, and current policy.

## 1. Establish a reproducible baseline

Use the same:

- sanitized input sample;
- Xray Core version;
- command-line options;
- HTTPS test endpoints;
- device and access type;
- approximate test duration.

Record:

- country and provider;
- broad region only;
- mobile/fixed/fiber/organizational access;
- IPv4, IPv6, or dual stack;
- local date/time and UTC offset;
- total, parsed, tested, accepted, and rejected counts;
- failure-stage distribution;
- median latency for accepted links.

Do not publish live VMess links, UUIDs, tokens, subscriber identifiers, precise addresses, or raw reports containing secrets.

## 2. Match settings to the observed failure pattern

| Observed condition | Recommended test adjustment | Limitation |
|---|---|---|
| Public source URLs do not load | Use `--seed-file --no-default-sources` | Tests only links already available locally |
| Source URLs require an existing proxy | Use `--source-proxy` for collection | Does not proxy the VMess probes themselves |
| Default probe endpoints are blocked | Supply multiple `--test-url` values | Endpoint choice can bias the result |
| High loss or unstable mobile access | Use `--attempts 5`, longer timeouts, and fewer workers | Longer tests still cannot repair a missing route |
| Provider rate limiting or local overload | Reduce `--workers` to 1 or 2 | Slower total run time |
| Partial international shutdown | Test one regional and one international endpoint | A regional success does not prove external reachability |
| Results differ by time | Repeat the same command in separate time windows | A snapshot is not a permanent rule |
| Results differ by ISP or access type | Create separate reports | Do not merge them into a country-wide conclusion |
| Suspected transport-specific filtering | Compare sanitized samples grouped by transport | This tool does not modify server transport settings |
| Suspected IPv4/IPv6 differences | Run separate network-level tests for each family | The current CLI does not force an address family |

## 3. Recommended conservative command

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
  --min-score 55 `
  --test-url "https://regional.example.net/generate_204" `
  --test-url "https://international.example.org/generate_204" `
  --output-prefix "results/network-a"
```

Replace the placeholder endpoints. Prefer small, stable HTTPS responses that do not require authentication, cookies, or redirects.

## 4. Interpreting common censorship patterns

### DNS manipulation

Symptoms may include inconsistent hostname resolution, bogus addresses, or failures that change between resolvers or networks.

For this tester:

- avoid assuming that source-download failure means the VMess server is dead;
- use local seed files when necessary;
- compare hostname-based and independently verified server samples only when you are authorized to do so;
- report the failure stage and network, not the private configuration.

### IP or port blocking

Repeated startup/request failures can be consistent with IP or port blocking, but can also result from an offline server, expired credentials, or routing failure.

Useful evidence requires:

- repetition;
- comparison from another provider or route;
- a known-good control configuration;
- sanitized logs showing the same failure stage.

### TLS/SNI interference

A TLS-related failure may be caused by certificate problems, incorrect SNI, server misconfiguration, filtering, or Xray-version incompatibility.

Do not use `--allow-insecure-server-cert` as the default fix. It weakens certificate validation and can hide a real configuration error. Use it only for an explicit diagnostic comparison and label the result insecure.

### DPI and protocol fingerprinting

When one transport family consistently fails while others pass on the same network and time window, the observation may justify further investigation. It is not proof by itself.

Compare:

- equal-sized samples;
- the same destinations where possible;
- the same test URLs and thresholds;
- multiple runs and providers.

Current Xray documentation recommends XHTTP over WebSocket or gRPC in some deployments because WebSocket has recognizable HTTP/1.1 characteristics and gRPC can present active-probing concerns. Server and client configurations must remain compatible. This tester does not convert transports.

### Active probing

This program does **not** detect whether a censor actively probes a server after observing traffic, and it does not protect the server from discovery. A configuration that passes now may fail later.

### Throttling and induced instability

Use several attempts and compare success rate, median latency, and variation. A single successful request should not be treated as stable service.

### Full shutdown, whitelisting, or missing international route

If the route to the external server does not exist, no timeout, retry, or transport choice can create connectivity. Preserve the result as evidence of the network condition rather than classifying every configuration as permanently invalid.

## 5. Country examples

### China

Measurement literature has documented DNS injection, TLS/SNI interference, and QUIC filtering. Use local seeds when public sources are unavailable, test regional and international endpoints separately, reduce concurrency, and repeat across providers and time windows.

### Russia

Centralized TSPU/DPI controls make provider, region, protocol, and time comparisons important. Test fixed and mobile access independently and compare failure stages rather than only accepted totals.

### Iran

Use `mci`, `irancell`, and `tci` only as operational presets. Separate mobile, fixed, fiber, and organizational access. Use `national` only with local seed data.

### Event-driven restrictions

In countries where restrictions change during elections, protests, examinations, conflicts, or local emergencies, run an identical baseline before, during, and after the event where safe and lawful.

## 6. Reporting results to this repository

Use the **Global network report** issue form.

A useful report contains:

1. Country and provider.
2. Broad region and access type.
3. Date/time and UTC offset.
4. IPv4/IPv6 status.
5. Python and Xray versions.
6. Sanitized command.
7. Sample size and transport distribution.
8. Accepted count, median latency, and failure stages.
9. Whether the result was reproduced.
10. Whether comparison from another network exists.

Avoid statements such as:

- "VMess works in country X";
- "operator Y permanently blocks transport Z";
- "this server is safe";
- "this configuration cannot be detected".

Prefer:

> On provider X, access type Y, broad region Z, at date/time T, the same sanitized sample produced N accepted configurations in two repeated runs. Most failures occurred at the request stage.

## 7. High-value contribution ideas

- Add translations without changing technical meaning.
- Improve parser compatibility using redacted fixtures.
- Add privacy-safe aggregation of failure stages.
- Add reproducible IPv4/IPv6 separation.
- Add optional protocol support in isolated modules with tests.
- Document one country's measurement methodology with reliable citations.
- Validate behavior against new Xray releases.

## References

- [OONI FAQ](https://ooni.org/support/faq/)
- [OONI global research reports](https://ooni.org/reports/)
- [OONI report on China blocking OONI](https://ooni.org/post/2023-china-blocks-ooni/)
- [USENIX Security 2025 study of QUIC censorship in China](https://www.usenix.org/conference/usenixsecurity25/presentation/zohaib)
- [Research on Russia's TSPU infrastructure](https://doi.org/10.5210/spir.v2024i0.15199)
- [Xray transport documentation](https://xtls.github.io/en/config/transports/)
- [Xray WebSocket documentation](https://xtls.github.io/en/config/transports/websocket.html)
- [Xray gRPC documentation](https://xtls.github.io/en/config/transports/grpc.html)
