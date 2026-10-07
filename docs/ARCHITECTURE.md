# Architecture and evidence contracts

Explicit artifacts and loopback endpoints → inventory → CBOM and policy findings → migration plan.
An isolated native OpenSSL lab supplies capability discovery, strict-profile TLS interoperability
and repeatable operation/handshake measurements. A static report consumes the actual JSON evidence.
No component automatically changes target infrastructure.

## Module interfaces

All modules use `cryptoagility.models.Asset` / `Inventory`, with schema version `1.0`.
Stable asset identifiers must derive from public metadata/artifact content, never private material.

- `inventory.scan(path: Path) -> Inventory`: explicit bounded file/directory discovery.
- `inventory.inspect_endpoint(host: str, port: int, ...) -> Inventory`: loopback only by default,
  verified peer identity, observation distinguished from supported-protocol probing.
- `cbom.export_json(inventory: Inventory) -> dict`, `cbom.export_csv(inventory: Inventory) -> str`:
  project-specific CBOM, not a claimed CycloneDX implementation.
- `policy.load_policy(path: Path) -> dict`; `policy.evaluate(inventory: Inventory, policy: dict) -> dict`:
  `schema_version`, `findings` (asset_id, outcome, reasons, migration_options), `summary`.
- `migration.plan(inventory: Inventory, policy: dict, matrix: dict | None = None,
  constraints: dict | None = None) -> dict`: `schema_version`, `readiness`, `items`, `reasons`;
  each item has asset_id, priority, reason, dependency, recommended_test, blocker, next_action.
- `tls.capabilities() -> dict`: actual version/provider/algorithm/group support.
- `tls.run_matrix(workdir: Path, ...) -> dict`: synthetic authenticated loopback experiments;
  `schema_version`, `environment`, `rows` with client/server, status, negotiated_group, tls_version,
  cipher_suite, certificate_type, policy_pass, error_reason. Profile/group mismatch fails closed.
- `benchmark.run_benchmarks(workdir: Path, iterations: int = 20, warmups: int = 3,
  profiles: list[str] | None = None) -> dict`: environment, raw samples, median/min/max,
  p95 only with sufficient samples, sizes, supported/unsupported/error distinctions.
- `reporting.render_report(results_dir: Path, output: Path) -> Path`: bounded validated evidence
  loading, escaping untrusted metadata, no private keys or remote assets.

The parent integrates CLI, scripts, Docker, CI and documentation. Implementation units own only
their modules and named tests; never shared registration or packaging files.

## Profiles

| Profile | TLS 1.3 key establishment | Authentication |
|---|---|---|
| Classical | X25519 | synthetic RSA-3072 or ECDSA certificate |
| Hybrid | X25519MLKEM768 | synthetic RSA-3072 certificate (classical auth is explicit) |
| PQC experiment | MLKEM768 | synthetic ML-DSA-65 certificate if stack supports it |

Availability is detected, not assumed. NIST algorithm standardization does not imply all TLS
group encodings or X.509 profiles are final standards, nor a FIPS 140 validated deployment.
