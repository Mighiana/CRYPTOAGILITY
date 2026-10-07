# CryptoAgility Lab — Post-Quantum Migration Engineering

[![CI](https://github.com/Mighiana/CRYPTOAGILITY/actions/workflows/ci.yml/badge.svg)](https://github.com/Mighiana/CRYPTOAGILITY/actions/workflows/ci.yml)

> How can an organization discover its current cryptographic dependencies and prepare systems
> for migration from classical public-key cryptography to post-quantum cryptography without
> blindly breaking compatibility?

CryptoAgility Lab is a reproducible, local engineering lab that answers that question with
evidence instead of slogans. It discovers crypto assets, exports a CBOM, evaluates them against
an explainable YAML policy, runs strict classical / hybrid / post-quantum TLS 1.3 experiments
with a pinned native OpenSSL 3.5.9 LTS, measures cost, and turns all of it into a migration plan
and an offline HTML report.

**Scope, honestly:** a research/engineering prototype that runs on one machine against a
*synthetic* fictional organization, using disposable keys and loopback (or a private container
network). It is not a production scanner, not deployed anywhere, and not evidence that any
organization is "PQC compliant". Classical RSA/ECC are not broken today; they are
quantum-vulnerable in the long term, which is why harvest-now-decrypt-later drives priority.

```
 artifacts / loopback endpoints
            │
   ┌────────▼────────┐    ┌──────────────┐    ┌──────────────────┐
   │ Inventory engine │──▶│ CBOM (JSON/CSV)│   │ OpenSSL 3.5.9 lab │ capabilities, strict
   └────────┬────────┘    └──────────────┘    │ TLS matrix,       │ profiles, negative
            │                                   │ benchmarks        │ controls
   ┌────────▼────────┐                         └────────┬─────────┘
   │  Policy engine   │ YAML rules, explainable          │
   └────────┬────────┘ outcomes per asset                │
            └──────────────┬─────────────────────────────┘
                  ┌────────▼────────┐      ┌───────────────────────┐
                  │ Migration planner│────▶│ Offline HTML report    │
                  └─────────────────┘      └───────────────────────┘
```

## Quick start

Requires Linux/macOS with Python 3.12, a C toolchain, `perl`, `curl` and `make`. Docker is
optional. Nothing in the system OpenSSL is changed.

```bash
git clone https://github.com/Mighiana/CRYPTOAGILITY.git && cd CRYPTOAGILITY
make setup     # .venv with pinned deps + OpenSSL 3.5.9 built into .tools/ (SHA-256 verified)
make test      # unit + real loopback TLS integration tests
make lab       # full pipeline -> results/*.json, results/cbom.csv, results/report.html
```

A committed example of this output lives in [`examples/sample-run/`](examples/sample-run/)
(download `report.html` and open it locally). Open `results/report.html` in any browser; it is a single self-contained file with no network
requests. `make help` lists all targets (`lint`, `test-fast`, `benchmark`, `report`,
`docker-lab`, `compose-interop`, `clean`).

## CLI

```bash
cryptoagility inventory scenario-dir/ -o inventory.json --cbom-dir out/   # discovery + CBOM
cryptoagility cbom inventory.json --format csv -o cbom.csv
cryptoagility policy inventory.json --policy policies/default.yaml        # explainable findings
cryptoagility capabilities                                                # what OpenSSL really supports
cryptoagility test --profile hybrid                                       # one strict handshake
cryptoagility matrix                                                      # client x server matrix
cryptoagility benchmark --profile hybrid --iterations 20 --warmups 3
cryptoagility plan inventory.json --matrix matrix.json --constraints scenario/constraints.yaml
cryptoagility report results/
cryptoagility inspect 127.0.0.1 8443 --cafile ca.pem                       # loopback by default
```

Every command prints a readable table, `--json` prints machine-readable evidence, and `-o`
writes it atomically. Exit codes: `0` ok, `1` gate failed (`--fail-on-noncompliant`,
`--fail-on-blocked`, failed handshake), `2` invalid input, `3` requested profile unsupported.

**No silent downgrade.** A profile pins TLS 1.3 and exactly one key-establishment group. If the
local stack cannot provide it, the command exits `3` with
`UNSUPPORTED CRYPTO PROFILE: … (ALGORITHM NOT AVAILABLE: …)`; it never falls back to classical.

## Components

| Component | Module | What it does |
|---|---|---|
| Inventory | `inventory.py` | Bounded scan of an explicit path: X.509 certs (RSA, ECDSA, Ed25519, ML-DSA, SLH-DSA), public keys, private-key presence, OpenSSL / application TLS configs (groups, versions, suites, sigalgs, profile). Loopback endpoint inspection with verified identity. Private keys are detected by type only; contents are never stored. |
| CBOM | `cbom.py` | Project-specific CBOM v1 (JSON + CSV, spreadsheet-formula-injection safe). Explicitly *not* CycloneDX. |
| Policy | `policy.py`, `policies/*.yaml` | Rule-based outcomes `APPROVED`, `ACCEPTABLE_FOR_NOW`, `DEPRECATED`, `MIGRATION_REQUIRED`, `EXPERIMENTAL`, `UNSUPPORTED`, each with reasons and migration options. Unknown evidence fails closed. Config tokens are routed to the right table (group / signature scheme / TLS version / suite). `constrained.yaml` models a generic long-lifetime constrained environment. |
| TLS lab | `tls.py` | Disposable synthetic PKI (RSA-3072, ECDSA, ML-DSA-65), strict `s_server`/`s_client` pairs on 127.0.0.1, negative controls (expired, wrong host, untrusted CA, PQC group with RSA cert). Negotiation success and policy compliance are reported separately. |
| Benchmarks | `benchmark.py` | Keygen/sign/verify, ML-KEM encaps/decaps, and handshakes; 20 iterations + 3 warmups by default; raw samples, median/min/max/p95, key/signature/ciphertext/handshake sizes, full environment metadata. |
| Planner | `migration.py` | `READY` / `PARTIALLY_READY` / `BLOCKED` / `UNKNOWN` with per-asset priority (`IMMEDIATE` … `MONITOR`), blocker, dependency, recommended test and next action; Markdown export. Uses declared constraints (data confidentiality years, system lifetime) — no guessed quantum arrival dates. |
| Report | `reporting/` | Single offline HTML file built only from the evidence JSON present; missing or invalid evidence is shown as such, untrusted metadata is escaped, secret-like strings are redacted. |
| Scenario | `scenario.py`, `scenario/fictional-org/` | Fictional organization: 12 service configs, 2 legacy clients, 11 regenerated public certificates (+ issuing CA). Private keys are deleted immediately after signing. |

## Results in this lab environment

From one `make lab` run on 2026-10-07: Intel Xeon Platinum 8375C (8 vCPU, KVM), Ubuntu 22.04,
OpenSSL 3.5.9 default provider (no oqs-provider), 20 iterations + 3 warmups. Re-run `make lab`
to reproduce on your hardware; numbers will differ.

**Inventory and policy (fictional org, `policies/default.yaml`).** 102 assets, 0 discovery
errors. 29 approved, 55 acceptable-for-now, 8 experimental, 3 migration-required, 6 deprecated,
1 unsupported (an unrecognised legacy cipher string — reported, not guessed). 52 assets are
quantum-vulnerable. Migration readiness: **BLOCKED** (expired and SHA-1-signed certificates, TLS 1.1,
3DES/AES-CBC suites, SHA-1 TLS signature schemes, RSA-2048, ffdhe2048, one unknown cipher).

**Interoperability matrix (TLS 1.3, strict single-group clients).**

| Server ↓ / client → | classical-only | hybrid-only | pqc-only | modern-agile | system OpenSSL 3.0.2 |
|---|---|---|---|---|---|
| classical (X25519, RSA-3072) | ✅ X25519 | ❌ no shared group | ❌ | ✅ X25519 | ✅ X25519 |
| hybrid (X25519MLKEM768, RSA-3072) | ❌ no shared group | ✅ hybrid | ❌ | ✅ hybrid | ❌ legacy client lacks ML-KEM |
| pqc (MLKEM768, ML-DSA-65) | ❌ | ❌ | ✅ MLKEM768 | ✅ MLKEM768 | ❌ |

Negative controls all fail as intended: expired cert, wrong hostname, untrusted CA
(`FAIL_CERTIFICATE`), and a server offering MLKEM768 with an RSA certificate
(`FAIL_PROFILE_MISMATCH` — the handshake succeeds, the profile check does not).

**Cost.** Handshake bytes read by the client: classical 3,056 B, hybrid 4,144 B (+36 %),
PQC with ML-DSA-65 chain 15,986 B (≈5.2×, dominated by the 11.3 kB certificate chain).
ML-KEM-768 ciphertext 1,088 B; ML-DSA-65 signature 3,309 B; SLH-DSA-SHA2-128s signature 7,856 B
vs RSA-3072 384 B / ECDSA P-256 ~71 B. Timings are whole `openssl` process wall-clock (a bare
`openssl version` costs ~1.7 ms), so they compare end-to-end CLI cost, not library speed:
median handshake classical 5.6 ms, hybrid 5.8 ms, PQC 5.7 ms; SLH-DSA-SHA2-128s signing 388 ms.

### Research questions

- **RQ1 – What can be discovered automatically?** Certificates, public keys, private-key presence (type only), key types,
  TLS group/version/suite/signature settings in configs, and live loopback handshakes. Not
  discovered: crypto inside binaries, HSM/KMS usage, or code-level API calls (out of scope v1).
- **RQ2 – Compatibility differences?** With strict clients, hybrid and PQC servers are
  unreachable from classical-only and legacy (OpenSSL 3.0) clients; a multi-group "agile" client
  reaches all three. Agility at the client is what makes staged migration possible.
- **RQ3 – Overheads?** Bytes on the wire grow modestly for hybrid key exchange and sharply for
  PQ signatures in the certificate chain; per-operation CPU cost is small except SLH-DSA signing.
- **RQ4 – Blockers?** Legacy protocol/cipher configurations and certificates (immediate), short
  RSA/FFDHE parameters (short-term), clients that cannot offer a hybrid group (matrix), and
  incomplete evidence (unknown cipher strings) — all surfaced with reasons.
- **RQ5 – Code change with abstraction?** In this lab, profiles are configuration tokens
  (`--profile`, service YAML `crypto_profile`), so switching classical→hybrid changes no
  application code. That is a property of this design, not a measurement of real codebases.

## Docker

```bash
make docker-lab        # pipeline inside the image, evidence in ./results
make compose-interop   # classical/hybrid/pqc servers + strict test client on a private network
```

The image builds the same checksum-pinned OpenSSL; containers run read-only, non-root, with all
capabilities dropped and no published ports. Servers generate synthetic certs at start-up and
share only CA certificates. In the slim image there is no system OpenSSL, so the
`system-legacy` client is reported `UNSUPPORTED` rather than faked.

## Security model

- Synthetic identities under `.test` only; keys are disposable (mode 0600, deleted on exit) and
  never written to evidence, reports, or git (`.gitignore` blocks `*.key`, `*.p12`, …).
- Endpoint inspection is loopback-only unless `--allow-remote` is given for a system you are
  authorized to test. No OS-wide scanning; only explicit paths.
- Inputs are size-bounded; symlinks are refused for inputs and outputs; writes are atomic.
- OpenSSL runs with `OPENSSL_CONF=/dev/null`, and the lab refuses to use the system OpenSSL
  unless `CRYPTOAGILITY_ALLOW_SYSTEM_OPENSSL=1`.
- No cryptographic primitive is implemented here; all crypto is OpenSSL or `cryptography`.

## Limitations

- ML-KEM, ML-DSA and SLH-DSA are NIST standards (FIPS 203/204/205); their TLS group code points
  and ML-DSA X.509/TLS integration are treated as experimental. The OpenSSL default provider is
  not a FIPS 140 validated module.
- Benchmarks are a single-machine, process-level view; they are not a library benchmark and do
  not model networks, constrained hardware, or load.
- The CBOM format is project-specific. Policies are examples to adapt, not regulatory guidance.
- The "constrained" profile is generic; it does not model real railway or industrial protocols.

## Repository layout

```
cryptoagility/        inventory, cbom, policy, migration, tls, benchmark, scenario, lab, cli, reporting/
policies/             default.yaml, constrained.yaml
scenario/             fictional-org configs + declared constraints
scripts/              setup-openssl.sh (pinned build), run-lab.sh
docker/, Dockerfile, docker-compose.yml
docs/                 ARCHITECTURE.md, STANDARDS.md
tests/                unit + integration tests (pytest -m integration for real handshakes)
```
