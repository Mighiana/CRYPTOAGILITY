# Migration plan

- Readiness: **BLOCKED**
- Policy: default (profile general)
- Generated: 2026-10-07T14:35:53.410894\+00:00
- No numerical score is produced; priorities are explained per item.

## Reasons

- 9 asset\(s\) blocked by policy or lab evidence: certs/rsa2048-legacy-portal-sha1.pem \(RSA / 2048 bits / RSA-2048\), certs/rsa2048-expired-reporting.pem \(RSA / 2048 bits / RSA-2048\), services/03-legacy-portal.yaml \(TLSv1.1\), services/03-legacy-portal.yaml \(3DES\), services/03-legacy-portal.yaml \(rsa\_pkcs1\_sha1\), services/03-legacy-portal.yaml \(AES-128-CBC\), certs/rsa2048-customer-api.pem \(RSA / 2048 bits / RSA-2048\), certs/rsa2048-public-web.pem \(RSA / 2048 bits / RSA-2048\), services/07-backup-archive.yaml \(ffdhe2048 / ffdhe2048\)
- 1 asset\(s\) have missing, unrecognised or footprint evidence gaps: clients/legacy-batch-client.cnf \(unrecognized\)

## Footprint

ESTIMATE: derived only from byte counts measured in the local lab; not network, MTU, latency or field evidence. No bandwidth budget was declared, so no budget comparison is made.
- grp-hybrid-x25519-mlkem768: median 5613.0 bytes over 2 sample(s) (matrix rows \(local loopback lab\))
- grp-mlkem: median 18163.5 bytes over 2 sample(s) (matrix rows \(local loopback lab\))
- grp-x25519: median 3448 bytes over 3 sample(s) (matrix rows \(local loopback lab\))

## Items

### cert-11eec10c69b79a1579481b32

| Field | Value |
|---|---|
| priority | IMMEDIATE |
| outcome | DEPRECATED |
| current_algorithm | RSA / 2048 bits / RSA-2048 |
| evidence_status | complete |
| reason | Priority IMMEDIATE: outcome DEPRECATED maps to IMMEDIATE under policy default; constraint factors noted but already at or above the escalation cap: declared data confidentiality of 12 years meets the profile threshold of 10 years \(harvest-now-decrypt-later exposure for quantum-vulnerable key establishment\); declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: signature\_algorithm: observed sha1WithRSAEncryption; rule sig-weak-hash: Signature uses a hash function this policy no longer permits for certificate signatures. |
| dependency | Issuing CA signature profile and every relying party's trust store and certificate parser; Lab evidence: 4 policy-compliant matrix row\(s\) demonstrate quantum-resistant key establishment, first row 6 \(hybrid-only / hybrid\); Lab evidence: 2 policy-compliant matrix row\(s\) demonstrate post-quantum authentication, first row 12 \(pqc-only / pqc\) |
| recommended_test | Issue a synthetic certificate with the target key and signature algorithm and verify chain validation in each client used with this certificate |
| blocker | Policy: DEPRECATED. signature\_algorithm: observed sha1WithRSAEncryption; rule sig-weak-hash: Signature uses a hash function this policy no longer permits for certificate signatures. |
| next_action | Replace or disable the dependency; it is below the policy minimum. |

Migration options:

- Re-issue the certificate with a SHA-2 based signature immediately
- Identify and update any client that still requires the weak signature

### cert-89b7c4a3d2227b32bedb9d2b

| Field | Value |
|---|---|
| priority | IMMEDIATE |
| outcome | DEPRECATED |
| current_algorithm | RSA / 2048 bits / RSA-2048 |
| evidence_status | complete |
| reason | Priority IMMEDIATE: outcome DEPRECATED maps to IMMEDIATE under policy default; constraint factors noted but already at or above the escalation cap: declared data confidentiality of 12 years meets the profile threshold of 10 years \(harvest-now-decrypt-later exposure for quantum-vulnerable key establishment\); declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: expiry: certificate expired at 2024-01-01T00:00:00\+00:00. An expired certificate is not a valid trust dependency under this policy. |
| dependency | Issuing CA signature profile and every relying party's trust store and certificate parser; Lab evidence: 4 policy-compliant matrix row\(s\) demonstrate quantum-resistant key establishment, first row 6 \(hybrid-only / hybrid\); Lab evidence: 2 policy-compliant matrix row\(s\) demonstrate post-quantum authentication, first row 12 \(pqc-only / pqc\) |
| recommended_test | Issue a synthetic certificate with the target key and signature algorithm and verify chain validation in each client used with this certificate |
| blocker | Policy: DEPRECATED. expiry: certificate expired at 2024-01-01T00:00:00\+00:00. An expired certificate is not a valid trust dependency under this policy. |
| next_action | Replace or disable the dependency; it is below the policy minimum. |

Migration options:

- Replace the certificate immediately
- Investigate why expiry was not detected by certificate tracking

### cfg-6805aec3378554525ce42c04

| Field | Value |
|---|---|
| priority | IMMEDIATE |
| outcome | DEPRECATED |
| current_algorithm | TLSv1.1 |
| evidence_status | complete |
| reason | Priority IMMEDIATE: outcome DEPRECATED maps to IMMEDIATE under policy default. Evidence: tls\_version: observed TLSv1.1; rule tls1.1: Protocol version not permitted by this policy. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | Policy: DEPRECATED. tls\_version: observed TLSv1.1; rule tls1.1: Protocol version not permitted by this policy. |
| next_action | Replace or disable the dependency; it is below the policy minimum. |

Migration options:

- Disable TLS 1.1 and require TLS 1.3 where clients support it
- Raise the server minimum protocol version
- Upgrade or isolate clients that cannot negotiate the minimum version

### cfg-dfb4bf6c36a1e43cb75047f4

| Field | Value |
|---|---|
| priority | IMMEDIATE |
| outcome | DEPRECATED |
| current_algorithm | 3DES |
| evidence_status | complete |
| reason | Priority IMMEDIATE: outcome DEPRECATED maps to IMMEDIATE under policy default. Evidence: cipher\_suite: observed 3DES; rule cs-legacy-generic: Non-AEAD or legacy symmetric cipher configuration is not permitted by this policy. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | Policy: DEPRECATED. cipher\_suite: observed 3DES; rule cs-legacy-generic: Non-AEAD or legacy symmetric cipher configuration is not permitted by this policy. |
| next_action | Replace or disable the dependency; it is below the policy minimum. |

Migration options:

- Remove the cipher and require an AEAD suite

### cfg-e9e61ce0ce9d7f85ba0f85f3

| Field | Value |
|---|---|
| priority | IMMEDIATE |
| outcome | DEPRECATED |
| current_algorithm | rsa\_pkcs1\_sha1 |
| evidence_status | complete |
| reason | Priority IMMEDIATE: outcome DEPRECATED maps to IMMEDIATE under policy default; constraint factors noted but already at or above the escalation cap: declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_signature: observed rsa\_pkcs1\_sha1; rule sig-tls-weak-hash: Configured TLS signature scheme uses a hash this policy no longer permits. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | Policy: DEPRECATED. configured\_signature: observed rsa\_pkcs1\_sha1; rule sig-tls-weak-hash: Configured TLS signature scheme uses a hash this policy no longer permits. |
| next_action | Replace or disable the dependency; it is below the policy minimum. |

Migration options:

- Remove the scheme from the configuration and confirm every client still connects

### cfg-fa40e4f1b53a3071b9f2248d

| Field | Value |
|---|---|
| priority | IMMEDIATE |
| outcome | DEPRECATED |
| current_algorithm | AES-128-CBC |
| evidence_status | complete |
| reason | Priority IMMEDIATE: outcome DEPRECATED maps to IMMEDIATE under policy default. Evidence: cipher\_suite: observed AES-128-CBC; rule cs-legacy-generic: Non-AEAD or legacy symmetric cipher configuration is not permitted by this policy. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | Policy: DEPRECATED. cipher\_suite: observed AES-128-CBC; rule cs-legacy-generic: Non-AEAD or legacy symmetric cipher configuration is not permitted by this policy. |
| next_action | Replace or disable the dependency; it is below the policy minimum. |

Migration options:

- Remove the cipher and require an AEAD suite

### cert-1854fe350d77b5cf9357d0e4

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | RSA / 3072 bits / RSA-3072 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared data confidentiality of 12 years meets the profile threshold of 10 years \(harvest-now-decrypt-later exposure for quantum-vulnerable key establishment\); declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: algorithm: observed RSA with key\_size=3072 \(band min\_bits=3072\); rule rsa: Meets this policy's 3072-bit classical minimum. RSA is quantum-vulnerable public-key cryptography and requires long-term PQ migration planning. |
| dependency | Issuing CA signature profile and every relying party's trust store and certificate parser; Lab evidence: 4 policy-compliant matrix row\(s\) demonstrate quantum-resistant key establishment, first row 6 \(hybrid-only / hybrid\); Lab evidence: 2 policy-compliant matrix row\(s\) demonstrate post-quantum authentication, first row 12 \(pqc-only / pqc\) |
| recommended_test | Exercise the target RSA-3072 or ML-DSA profile in the local TLS lab with each client |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Re-issue with RSA-3072 or larger as an interim classical step
- Plan a hybrid transition \(classical plus ML-KEM key establishment\) for TLS paths
- Evaluate an ML-DSA certificate profile in the PQC-capable test environment
- Redesign the certificate/profile so the algorithm is configurable rather than hard-coded
- Plan CA migration to an ML-DSA signature profile once relying parties are tested
- Keep issuance profiles configurable to allow a staged CA transition

### cert-25cf4018a6c728447189fe59

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | ECDSA / 256 bits / P-256 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared data confidentiality of 12 years meets the profile threshold of 10 years \(harvest-now-decrypt-later exposure for quantum-vulnerable key establishment\); declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: algorithm: observed ECDSA parameter set P-256; rule ec: Permitted NIST curve. Elliptic-curve cryptography is quantum-vulnerable public-key cryptography and requires long-term PQ migration planning. |
| dependency | Issuing CA signature profile and every relying party's trust store and certificate parser; Lab evidence: 4 policy-compliant matrix row\(s\) demonstrate quantum-resistant key establishment, first row 6 \(hybrid-only / hybrid\); Lab evidence: 2 policy-compliant matrix row\(s\) demonstrate post-quantum authentication, first row 12 \(pqc-only / pqc\) |
| recommended_test | Issue a synthetic certificate with the target key and signature algorithm and verify chain validation in each client used with this certificate |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Keep the permitted curve as an interim classical step while PQ profiles are tested
- Plan a hybrid transition for key establishment \(for example X25519MLKEM768 where supported\)
- Evaluate an ML-DSA certificate profile in the PQC-capable test environment
- Plan CA migration to an ML-DSA signature profile once relying parties are tested
- Keep issuance profiles configurable to allow a staged CA transition

### cert-2c4f6caaa994823d4c181589

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | RSA / 3072 bits / RSA-3072 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared data confidentiality of 12 years meets the profile threshold of 10 years \(harvest-now-decrypt-later exposure for quantum-vulnerable key establishment\); declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: algorithm: observed RSA with key\_size=3072 \(band min\_bits=3072\); rule rsa: Meets this policy's 3072-bit classical minimum. RSA is quantum-vulnerable public-key cryptography and requires long-term PQ migration planning. |
| dependency | Issuing CA signature profile and every relying party's trust store and certificate parser; Lab evidence: 4 policy-compliant matrix row\(s\) demonstrate quantum-resistant key establishment, first row 6 \(hybrid-only / hybrid\); Lab evidence: 2 policy-compliant matrix row\(s\) demonstrate post-quantum authentication, first row 12 \(pqc-only / pqc\) |
| recommended_test | Exercise the target RSA-3072 or ML-DSA profile in the local TLS lab with each client |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Re-issue with RSA-3072 or larger as an interim classical step
- Plan a hybrid transition \(classical plus ML-KEM key establishment\) for TLS paths
- Evaluate an ML-DSA certificate profile in the PQC-capable test environment
- Redesign the certificate/profile so the algorithm is configurable rather than hard-coded
- Plan CA migration to an ML-DSA signature profile once relying parties are tested
- Keep issuance profiles configurable to allow a staged CA transition

### cert-347495844929e984cc91ad68

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | RSA / 4096 bits / RSA-4096 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared data confidentiality of 12 years meets the profile threshold of 10 years \(harvest-now-decrypt-later exposure for quantum-vulnerable key establishment\); declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: algorithm: observed RSA with key\_size=4096 \(band min\_bits=3072\); rule rsa: Meets this policy's 3072-bit classical minimum. RSA is quantum-vulnerable public-key cryptography and requires long-term PQ migration planning. |
| dependency | Issuing CA signature profile and every relying party's trust store and certificate parser; Lab evidence: 4 policy-compliant matrix row\(s\) demonstrate quantum-resistant key establishment, first row 6 \(hybrid-only / hybrid\); Lab evidence: 2 policy-compliant matrix row\(s\) demonstrate post-quantum authentication, first row 12 \(pqc-only / pqc\) |
| recommended_test | Exercise the target RSA-3072 or ML-DSA profile in the local TLS lab with each client |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Re-issue with RSA-3072 or larger as an interim classical step
- Plan a hybrid transition \(classical plus ML-KEM key establishment\) for TLS paths
- Evaluate an ML-DSA certificate profile in the PQC-capable test environment
- Redesign the certificate/profile so the algorithm is configurable rather than hard-coded
- Plan CA migration to an ML-DSA signature profile once relying parties are tested
- Keep issuance profiles configurable to allow a staged CA transition

### cert-579149dcd569007d47fc51ef

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | ECDSA / 256 bits / P-256 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared data confidentiality of 12 years meets the profile threshold of 10 years \(harvest-now-decrypt-later exposure for quantum-vulnerable key establishment\); declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: algorithm: observed ECDSA parameter set P-256; rule ec: Permitted NIST curve. Elliptic-curve cryptography is quantum-vulnerable public-key cryptography and requires long-term PQ migration planning. |
| dependency | Issuing CA signature profile and every relying party's trust store and certificate parser; Lab evidence: 4 policy-compliant matrix row\(s\) demonstrate quantum-resistant key establishment, first row 6 \(hybrid-only / hybrid\); Lab evidence: 2 policy-compliant matrix row\(s\) demonstrate post-quantum authentication, first row 12 \(pqc-only / pqc\) |
| recommended_test | Issue a synthetic certificate with the target key and signature algorithm and verify chain validation in each client used with this certificate |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Keep the permitted curve as an interim classical step while PQ profiles are tested
- Plan a hybrid transition for key establishment \(for example X25519MLKEM768 where supported\)
- Evaluate an ML-DSA certificate profile in the PQC-capable test environment
- Plan CA migration to an ML-DSA signature profile once relying parties are tested
- Keep issuance profiles configurable to allow a staged CA transition

### cert-77d3056bb6013acde4c036af

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | RSA / 3072 bits / RSA-3072 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared data confidentiality of 12 years meets the profile threshold of 10 years \(harvest-now-decrypt-later exposure for quantum-vulnerable key establishment\); declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: algorithm: observed RSA with key\_size=3072 \(band min\_bits=3072\); rule rsa: Meets this policy's 3072-bit classical minimum. RSA is quantum-vulnerable public-key cryptography and requires long-term PQ migration planning. |
| dependency | Issuing CA signature profile and every relying party's trust store and certificate parser; Lab evidence: 4 policy-compliant matrix row\(s\) demonstrate quantum-resistant key establishment, first row 6 \(hybrid-only / hybrid\); Lab evidence: 2 policy-compliant matrix row\(s\) demonstrate post-quantum authentication, first row 12 \(pqc-only / pqc\) |
| recommended_test | Exercise the target RSA-3072 or ML-DSA profile in the local TLS lab with each client |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Re-issue with RSA-3072 or larger as an interim classical step
- Plan a hybrid transition \(classical plus ML-KEM key establishment\) for TLS paths
- Evaluate an ML-DSA certificate profile in the PQC-capable test environment
- Redesign the certificate/profile so the algorithm is configurable rather than hard-coded
- Plan CA migration to an ML-DSA signature profile once relying parties are tested
- Keep issuance profiles configurable to allow a staged CA transition

### cert-79443cbc63931cf7f7693f7e

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | MIGRATION\_REQUIRED |
| current_algorithm | RSA / 2048 bits / RSA-2048 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome MIGRATION\_REQUIRED maps to SHORT\_TERM under policy default; constraint factors noted but already at or above the escalation cap: declared data confidentiality of 12 years meets the profile threshold of 10 years \(harvest-now-decrypt-later exposure for quantum-vulnerable key establishment\); declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: algorithm: observed RSA with key\_size=2048 \(band min\_bits=2048\); rule rsa: Below this policy's 3072-bit classical minimum. Quantum-vulnerable public-key dependency identified; migration is required. |
| dependency | Issuing CA signature profile and every relying party's trust store and certificate parser; Lab evidence: 4 policy-compliant matrix row\(s\) demonstrate quantum-resistant key establishment, first row 6 \(hybrid-only / hybrid\); Lab evidence: 2 policy-compliant matrix row\(s\) demonstrate post-quantum authentication, first row 12 \(pqc-only / pqc\) |
| recommended_test | Exercise the target RSA-3072 or ML-DSA profile in the local TLS lab with each client |
| blocker | Policy: MIGRATION\_REQUIRED. algorithm: observed RSA with key\_size=2048 \(band min\_bits=2048\); rule rsa: Below this policy's 3072-bit classical minimum. Quantum-vulnerable public-key dependency identified; migration is required. |
| next_action | Test the policy-compliant target profile in the lab, then plan the change with the asset owner. |

Migration options:

- Re-issue with RSA-3072 or larger as an interim classical step
- Plan a hybrid transition \(classical plus ML-KEM key establishment\) for TLS paths
- Evaluate an ML-DSA certificate profile in the PQC-capable test environment
- Redesign the certificate/profile so the algorithm is configurable rather than hard-coded

### cert-9a1077038b43ed323881f053

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | MIGRATION\_REQUIRED |
| current_algorithm | RSA / 2048 bits / RSA-2048 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome MIGRATION\_REQUIRED maps to SHORT\_TERM under policy default; constraint factors noted but already at or above the escalation cap: declared data confidentiality of 12 years meets the profile threshold of 10 years \(harvest-now-decrypt-later exposure for quantum-vulnerable key establishment\); declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: algorithm: observed RSA with key\_size=2048 \(band min\_bits=2048\); rule rsa: Below this policy's 3072-bit classical minimum. Quantum-vulnerable public-key dependency identified; migration is required. |
| dependency | Issuing CA signature profile and every relying party's trust store and certificate parser; Lab evidence: 4 policy-compliant matrix row\(s\) demonstrate quantum-resistant key establishment, first row 6 \(hybrid-only / hybrid\); Lab evidence: 2 policy-compliant matrix row\(s\) demonstrate post-quantum authentication, first row 12 \(pqc-only / pqc\) |
| recommended_test | Exercise the target RSA-3072 or ML-DSA profile in the local TLS lab with each client |
| blocker | Policy: MIGRATION\_REQUIRED. algorithm: observed RSA with key\_size=2048 \(band min\_bits=2048\); rule rsa: Below this policy's 3072-bit classical minimum. Quantum-vulnerable public-key dependency identified; migration is required. |
| next_action | Test the policy-compliant target profile in the lab, then plan the change with the asset owner. |

Migration options:

- Re-issue with RSA-3072 or larger as an interim classical step
- Plan a hybrid transition \(classical plus ML-KEM key establishment\) for TLS paths
- Evaluate an ML-DSA certificate profile in the PQC-capable test environment
- Redesign the certificate/profile so the algorithm is configurable rather than hard-coded

### cert-e7a9922c59aa3e5cb3d19d51

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | ECDSA / 384 bits / P-384 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared data confidentiality of 12 years meets the profile threshold of 10 years \(harvest-now-decrypt-later exposure for quantum-vulnerable key establishment\); declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: algorithm: observed ECDSA parameter set P-384; rule ec: Permitted NIST curve; quantum-vulnerable public-key cryptography requiring long-term PQ migration planning. |
| dependency | Issuing CA signature profile and every relying party's trust store and certificate parser; Lab evidence: 4 policy-compliant matrix row\(s\) demonstrate quantum-resistant key establishment, first row 6 \(hybrid-only / hybrid\); Lab evidence: 2 policy-compliant matrix row\(s\) demonstrate post-quantum authentication, first row 12 \(pqc-only / pqc\) |
| recommended_test | Issue a synthetic certificate with the target key and signature algorithm and verify chain validation in each client used with this certificate |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Keep the permitted curve as an interim classical step while PQ profiles are tested
- Plan a hybrid transition for key establishment \(for example X25519MLKEM768 where supported\)
- Evaluate an ML-DSA certificate profile in the PQC-capable test environment
- Plan CA migration to an ML-DSA signature profile once relying parties are tested
- Keep issuance profiles configurable to allow a staged CA transition

### cfg-053e6100185ca43f6803a03a

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | secp256r1 / secp256r1 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_group: observed secp256r1; rule grp-nist-ec: Classical elliptic-curve key establishment; quantum-vulnerable and a harvest-now-decrypt-later planning factor for long-lived confidential traffic. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test SecP256r1MLKEM768 or SecP384r1MLKEM1024 hybrid key establishment where supported
- Pin the required group in tests to detect silent fallback

### cfg-193ce6bec9fc75937dc22d48

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | X25519 / X25519 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_group: observed X25519; rule grp-x25519: Classical key establishment; quantum-vulnerable and a harvest-now-decrypt-later planning factor for long-lived confidential traffic. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Run the matrix with X25519MLKEM768 pinned and confirm the endpoint does not fall back to X25519 |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test X25519MLKEM768 hybrid key establishment with this endpoint's clients
- Pin the required group in tests to detect silent fallback

### cfg-1dacdc8e1d9c3243f9a31dd4

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | ecdsa\_secp256r1\_sha256 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_signature: observed ecdsa\_secp256r1\_sha256; rule sig-tls-ecdsa-sha2: Configured TLS ECDSA signature scheme with a SHA-2 hash; quantum-vulnerable authentication requiring long-term PQ migration planning. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test an ML-DSA authentication profile in the lab with every client of this service

### cfg-344e45b49eda1cb6274c310d

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | classical |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared data confidentiality of 12 years meets the profile threshold of 10 years \(harvest-now-decrypt-later exposure for quantum-vulnerable key establishment\); declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: algorithm: observed classical; rule profile-classical: Declared crypto profile "classical" selects quantum-vulnerable key establishment and authentication; acceptable for now, with PQ migration planning required. |
| dependency | Application code paths that read this cryptographic setting; Lab evidence: 4 policy-compliant matrix row\(s\) demonstrate quantum-resistant key establishment, first row 6 \(hybrid-only / hybrid\); Lab evidence: 2 policy-compliant matrix row\(s\) demonstrate post-quantum authentication, first row 12 \(pqc-only / pqc\) |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Switch the declared profile to hybrid in a test deployment and run the interoperability matrix
- Keep the profile configurable so the switch needs no application code change

### cfg-35fbedf06a4e14da3bdf0f09

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | classical |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared data confidentiality of 12 years meets the profile threshold of 10 years \(harvest-now-decrypt-later exposure for quantum-vulnerable key establishment\); declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: algorithm: observed classical; rule profile-classical: Declared crypto profile "classical" selects quantum-vulnerable key establishment and authentication; acceptable for now, with PQ migration planning required. |
| dependency | Application code paths that read this cryptographic setting; Lab evidence: 4 policy-compliant matrix row\(s\) demonstrate quantum-resistant key establishment, first row 6 \(hybrid-only / hybrid\); Lab evidence: 2 policy-compliant matrix row\(s\) demonstrate post-quantum authentication, first row 12 \(pqc-only / pqc\) |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Switch the declared profile to hybrid in a test deployment and run the interoperability matrix
- Keep the profile configurable so the switch needs no application code change

### cfg-3640e1379b8d83774b6536f7

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | ecdsa\_secp256r1\_sha256 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_signature: observed ecdsa\_secp256r1\_sha256; rule sig-tls-ecdsa-sha2: Configured TLS ECDSA signature scheme with a SHA-2 hash; quantum-vulnerable authentication requiring long-term PQ migration planning. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test an ML-DSA authentication profile in the lab with every client of this service

### cfg-4e28fbe6ad058ee814dcf578

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | classical |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared data confidentiality of 12 years meets the profile threshold of 10 years \(harvest-now-decrypt-later exposure for quantum-vulnerable key establishment\); declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: algorithm: observed classical; rule profile-classical: Declared crypto profile "classical" selects quantum-vulnerable key establishment and authentication; acceptable for now, with PQ migration planning required. |
| dependency | Application code paths that read this cryptographic setting; Lab evidence: 4 policy-compliant matrix row\(s\) demonstrate quantum-resistant key establishment, first row 6 \(hybrid-only / hybrid\); Lab evidence: 2 policy-compliant matrix row\(s\) demonstrate post-quantum authentication, first row 12 \(pqc-only / pqc\) |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Switch the declared profile to hybrid in a test deployment and run the interoperability matrix
- Keep the profile configurable so the switch needs no application code change

### cfg-508f0f9a10be42f225238bb5

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | ecdsa\_secp256r1\_sha256 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_signature: observed ecdsa\_secp256r1\_sha256; rule sig-tls-ecdsa-sha2: Configured TLS ECDSA signature scheme with a SHA-2 hash; quantum-vulnerable authentication requiring long-term PQ migration planning. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test an ML-DSA authentication profile in the lab with every client of this service

### cfg-583adf8061949c95d036ae3a

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | X25519 / X25519 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_group: observed X25519; rule grp-x25519: Classical key establishment; quantum-vulnerable and a harvest-now-decrypt-later planning factor for long-lived confidential traffic. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Run the matrix with X25519MLKEM768 pinned and confirm the endpoint does not fall back to X25519 |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test X25519MLKEM768 hybrid key establishment with this endpoint's clients
- Pin the required group in tests to detect silent fallback

### cfg-6254131c77f080b386d7e219

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | X25519 / X25519 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_group: observed X25519; rule grp-x25519: Classical key establishment; quantum-vulnerable and a harvest-now-decrypt-later planning factor for long-lived confidential traffic. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Run the matrix with X25519MLKEM768 pinned and confirm the endpoint does not fall back to X25519 |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test X25519MLKEM768 hybrid key establishment with this endpoint's clients
- Pin the required group in tests to detect silent fallback

### cfg-6a6105ce614ecbdf15c6e428

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | secp256r1 / secp256r1 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_group: observed secp256r1; rule grp-nist-ec: Classical elliptic-curve key establishment; quantum-vulnerable and a harvest-now-decrypt-later planning factor for long-lived confidential traffic. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test SecP256r1MLKEM768 or SecP384r1MLKEM1024 hybrid key establishment where supported
- Pin the required group in tests to detect silent fallback

### cfg-6b34ebc662aa9c3583f60637

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | MIGRATION\_REQUIRED |
| current_algorithm | ffdhe2048 / ffdhe2048 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome MIGRATION\_REQUIRED maps to SHORT\_TERM under policy default; constraint factors noted but already at or above the escalation cap: declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_group: observed ffdhe2048; rule grp-ffdhe2048: Finite-field group below this policy's 3072-bit minimum. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | Policy: MIGRATION\_REQUIRED. configured\_group: observed ffdhe2048; rule grp-ffdhe2048: Finite-field group below this policy's 3072-bit minimum. |
| next_action | Test the policy-compliant target profile in the lab, then plan the change with the asset owner. |

Migration options:

- Remove ffdhe2048 from the server group list and test a hybrid ML-KEM group

### cfg-6ea56e3933fb2a7097557bba

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | secp256r1 / secp256r1 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_group: observed secp256r1; rule grp-nist-ec: Classical elliptic-curve key establishment; quantum-vulnerable and a harvest-now-decrypt-later planning factor for long-lived confidential traffic. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test SecP256r1MLKEM768 or SecP384r1MLKEM1024 hybrid key establishment where supported
- Pin the required group in tests to detect silent fallback

### cfg-78e7e7f9de763bb89c6099c5

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | secp256r1 / secp256r1 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_group: observed secp256r1; rule grp-nist-ec: Classical elliptic-curve key establishment; quantum-vulnerable and a harvest-now-decrypt-later planning factor for long-lived confidential traffic. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test SecP256r1MLKEM768 or SecP384r1MLKEM1024 hybrid key establishment where supported
- Pin the required group in tests to detect silent fallback

### cfg-7ca3e9deca428e3cbd0f4b45

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | classical |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared data confidentiality of 12 years meets the profile threshold of 10 years \(harvest-now-decrypt-later exposure for quantum-vulnerable key establishment\); declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: algorithm: observed classical; rule profile-classical: Declared crypto profile "classical" selects quantum-vulnerable key establishment and authentication; acceptable for now, with PQ migration planning required. |
| dependency | Application code paths that read this cryptographic setting; Lab evidence: 4 policy-compliant matrix row\(s\) demonstrate quantum-resistant key establishment, first row 6 \(hybrid-only / hybrid\); Lab evidence: 2 policy-compliant matrix row\(s\) demonstrate post-quantum authentication, first row 12 \(pqc-only / pqc\) |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Switch the declared profile to hybrid in a test deployment and run the interoperability matrix
- Keep the profile configurable so the switch needs no application code change

### cfg-7ea00bb222ef8c37414971b7

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | classical |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared data confidentiality of 12 years meets the profile threshold of 10 years \(harvest-now-decrypt-later exposure for quantum-vulnerable key establishment\); declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: algorithm: observed classical; rule profile-classical: Declared crypto profile "classical" selects quantum-vulnerable key establishment and authentication; acceptable for now, with PQ migration planning required. |
| dependency | Application code paths that read this cryptographic setting; Lab evidence: 4 policy-compliant matrix row\(s\) demonstrate quantum-resistant key establishment, first row 6 \(hybrid-only / hybrid\); Lab evidence: 2 policy-compliant matrix row\(s\) demonstrate post-quantum authentication, first row 12 \(pqc-only / pqc\) |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Switch the declared profile to hybrid in a test deployment and run the interoperability matrix
- Keep the profile configurable so the switch needs no application code change

### cfg-86d9a1b15c7077b093866eb0

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | ecdsa\_secp384r1\_sha384 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_signature: observed ecdsa\_secp384r1\_sha384; rule sig-tls-ecdsa-sha2: Configured TLS ECDSA signature scheme with a SHA-2 hash; quantum-vulnerable authentication requiring long-term PQ migration planning. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test an ML-DSA authentication profile in the lab with every client of this service

### cfg-8e5aeb58d8aea8b4ec3a9b99

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | rsa\_pss\_rsae\_sha512 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_signature: observed rsa\_pss\_rsae\_sha512; rule sig-tls-rsa-sha2: Configured TLS RSA signature scheme with a SHA-2 hash; quantum-vulnerable authentication requiring long-term PQ migration planning. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test an ML-DSA authentication profile in the lab with every client of this service
- Keep signature schemes configurable so they can be changed without code changes

### cfg-90209189fcbec9e84dcda072

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | rsa\_pss\_rsae\_sha256 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_signature: observed rsa\_pss\_rsae\_sha256; rule sig-tls-rsa-sha2: Configured TLS RSA signature scheme with a SHA-2 hash; quantum-vulnerable authentication requiring long-term PQ migration planning. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test an ML-DSA authentication profile in the lab with every client of this service
- Keep signature schemes configurable so they can be changed without code changes

### cfg-977c8d1a0a8975c28f382438

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | rsa\_pss\_rsae\_sha256 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_signature: observed rsa\_pss\_rsae\_sha256; rule sig-tls-rsa-sha2: Configured TLS RSA signature scheme with a SHA-2 hash; quantum-vulnerable authentication requiring long-term PQ migration planning. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test an ML-DSA authentication profile in the lab with every client of this service
- Keep signature schemes configurable so they can be changed without code changes

### cfg-a31d32162096ef37e51b3a12

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | secp256r1 / secp256r1 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_group: observed secp256r1; rule grp-nist-ec: Classical elliptic-curve key establishment; quantum-vulnerable and a harvest-now-decrypt-later planning factor for long-lived confidential traffic. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test SecP256r1MLKEM768 or SecP384r1MLKEM1024 hybrid key establishment where supported
- Pin the required group in tests to detect silent fallback

### cfg-a3d7f40ae8e09ae95b5f4c05

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | classical |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared data confidentiality of 12 years meets the profile threshold of 10 years \(harvest-now-decrypt-later exposure for quantum-vulnerable key establishment\); declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: algorithm: observed classical; rule profile-classical: Declared crypto profile "classical" selects quantum-vulnerable key establishment and authentication; acceptable for now, with PQ migration planning required. |
| dependency | Application code paths that read this cryptographic setting; Lab evidence: 4 policy-compliant matrix row\(s\) demonstrate quantum-resistant key establishment, first row 6 \(hybrid-only / hybrid\); Lab evidence: 2 policy-compliant matrix row\(s\) demonstrate post-quantum authentication, first row 12 \(pqc-only / pqc\) |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Switch the declared profile to hybrid in a test deployment and run the interoperability matrix
- Keep the profile configurable so the switch needs no application code change

### cfg-b0739879d8473120a4814aeb

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | rsa\_pss\_rsae\_sha256 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_signature: observed rsa\_pss\_rsae\_sha256; rule sig-tls-rsa-sha2: Configured TLS RSA signature scheme with a SHA-2 hash; quantum-vulnerable authentication requiring long-term PQ migration planning. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test an ML-DSA authentication profile in the lab with every client of this service
- Keep signature schemes configurable so they can be changed without code changes

### cfg-c3948c68f08641a067dbd666

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | X25519 / X25519 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_group: observed X25519; rule grp-x25519: Classical key establishment; quantum-vulnerable and a harvest-now-decrypt-later planning factor for long-lived confidential traffic. |
| dependency | Every process that loads this OpenSSL configuration |
| recommended_test | Run the matrix with X25519MLKEM768 pinned and confirm the endpoint does not fall back to X25519 |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test X25519MLKEM768 hybrid key establishment with this endpoint's clients
- Pin the required group in tests to detect silent fallback

### cfg-c3b4b5d15a8513982ce16281

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | rsa\_pkcs1\_sha256 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_signature: observed rsa\_pkcs1\_sha256; rule sig-tls-rsa-sha2: Configured TLS RSA signature scheme with a SHA-2 hash; quantum-vulnerable authentication requiring long-term PQ migration planning. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test an ML-DSA authentication profile in the lab with every client of this service
- Keep signature schemes configurable so they can be changed without code changes

### cfg-c4b30fc3ba81547f052587d3

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | classical |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared data confidentiality of 12 years meets the profile threshold of 10 years \(harvest-now-decrypt-later exposure for quantum-vulnerable key establishment\); declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: algorithm: observed classical; rule profile-classical: Declared crypto profile "classical" selects quantum-vulnerable key establishment and authentication; acceptable for now, with PQ migration planning required. |
| dependency | Application code paths that read this cryptographic setting; Lab evidence: 4 policy-compliant matrix row\(s\) demonstrate quantum-resistant key establishment, first row 6 \(hybrid-only / hybrid\); Lab evidence: 2 policy-compliant matrix row\(s\) demonstrate post-quantum authentication, first row 12 \(pqc-only / pqc\) |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Switch the declared profile to hybrid in a test deployment and run the interoperability matrix
- Keep the profile configurable so the switch needs no application code change

### cfg-c5cbd421e2528e407f88561b

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | rsa\_pkcs1\_sha256 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_signature: observed rsa\_pkcs1\_sha256; rule sig-tls-rsa-sha2: Configured TLS RSA signature scheme with a SHA-2 hash; quantum-vulnerable authentication requiring long-term PQ migration planning. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test an ML-DSA authentication profile in the lab with every client of this service
- Keep signature schemes configurable so they can be changed without code changes

### cfg-c754debf0f24b1aece11e89d

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | secp256r1 / secp256r1 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_group: observed secp256r1; rule grp-nist-ec: Classical elliptic-curve key establishment; quantum-vulnerable and a harvest-now-decrypt-later planning factor for long-lived confidential traffic. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test SecP256r1MLKEM768 or SecP384r1MLKEM1024 hybrid key establishment where supported
- Pin the required group in tests to detect silent fallback

### cfg-c80268a8bc924b81ba0a6ea2

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | ECDSA\+SHA256 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_signature: observed ECDSA\+SHA256; rule sig-tls-ecdsa-sha2: Configured TLS ECDSA signature scheme with a SHA-2 hash; quantum-vulnerable authentication requiring long-term PQ migration planning. |
| dependency | Every process that loads this OpenSSL configuration |
| recommended_test | Load the configuration in an isolated test process and list the effective groups and algorithms |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test an ML-DSA authentication profile in the lab with every client of this service

### cfg-c9159c428d39c5640de22946

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | rsa\_pss\_rsae\_sha256 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_signature: observed rsa\_pss\_rsae\_sha256; rule sig-tls-rsa-sha2: Configured TLS RSA signature scheme with a SHA-2 hash; quantum-vulnerable authentication requiring long-term PQ migration planning. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test an ML-DSA authentication profile in the lab with every client of this service
- Keep signature schemes configurable so they can be changed without code changes

### cfg-cab60df92e64ce4f8e9eb689

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | X25519 / X25519 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_group: observed X25519; rule grp-x25519: Classical key establishment; quantum-vulnerable and a harvest-now-decrypt-later planning factor for long-lived confidential traffic. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Run the matrix with X25519MLKEM768 pinned and confirm the endpoint does not fall back to X25519 |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test X25519MLKEM768 hybrid key establishment with this endpoint's clients
- Pin the required group in tests to detect silent fallback

### cfg-cc62faa3f98aa2755ff1e32b

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | rsa\_pss\_rsae\_sha384 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_signature: observed rsa\_pss\_rsae\_sha384; rule sig-tls-rsa-sha2: Configured TLS RSA signature scheme with a SHA-2 hash; quantum-vulnerable authentication requiring long-term PQ migration planning. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test an ML-DSA authentication profile in the lab with every client of this service
- Keep signature schemes configurable so they can be changed without code changes

### cfg-cf56d76e0bc6b8b43023cfb6

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | secp256r1 / secp256r1 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_group: observed secp256r1; rule grp-nist-ec: Classical elliptic-curve key establishment; quantum-vulnerable and a harvest-now-decrypt-later planning factor for long-lived confidential traffic. |
| dependency | Every process that loads this OpenSSL configuration |
| recommended_test | Load the configuration in an isolated test process and list the effective groups and algorithms |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test SecP256r1MLKEM768 or SecP384r1MLKEM1024 hybrid key establishment where supported
- Pin the required group in tests to detect silent fallback

### cfg-d0043fea3fdf692011064964

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | RSA\+SHA256 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_signature: observed RSA\+SHA256; rule sig-tls-rsa-sha2: Configured TLS RSA signature scheme with a SHA-2 hash; quantum-vulnerable authentication requiring long-term PQ migration planning. |
| dependency | Every process that loads this OpenSSL configuration |
| recommended_test | Load the configuration in an isolated test process and list the effective groups and algorithms |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test an ML-DSA authentication profile in the lab with every client of this service
- Keep signature schemes configurable so they can be changed without code changes

### cfg-d26a01c49e66f0bc4d3d3cfc

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | X25519 / X25519 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_group: observed X25519; rule grp-x25519: Classical key establishment; quantum-vulnerable and a harvest-now-decrypt-later planning factor for long-lived confidential traffic. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Run the matrix with X25519MLKEM768 pinned and confirm the endpoint does not fall back to X25519 |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test X25519MLKEM768 hybrid key establishment with this endpoint's clients
- Pin the required group in tests to detect silent fallback

### cfg-f0846b02846ec1ea559d871f

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | secp256r1 / secp256r1 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_group: observed secp256r1; rule grp-nist-ec: Classical elliptic-curve key establishment; quantum-vulnerable and a harvest-now-decrypt-later planning factor for long-lived confidential traffic. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test SecP256r1MLKEM768 or SecP384r1MLKEM1024 hybrid key establishment where supported
- Pin the required group in tests to detect silent fallback

### cfg-f387a75c5f888b8534a0d1a5

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | classical |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared data confidentiality of 12 years meets the profile threshold of 10 years \(harvest-now-decrypt-later exposure for quantum-vulnerable key establishment\); declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: algorithm: observed classical; rule profile-classical: Declared crypto profile "classical" selects quantum-vulnerable key establishment and authentication; acceptable for now, with PQ migration planning required. |
| dependency | Application code paths that read this cryptographic setting; Lab evidence: 4 policy-compliant matrix row\(s\) demonstrate quantum-resistant key establishment, first row 6 \(hybrid-only / hybrid\); Lab evidence: 2 policy-compliant matrix row\(s\) demonstrate post-quantum authentication, first row 12 \(pqc-only / pqc\) |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Switch the declared profile to hybrid in a test deployment and run the interoperability matrix
- Keep the profile configurable so the switch needs no application code change

### cfg-f5084f7d9e35b2b04c82153f

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | classical |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared data confidentiality of 12 years meets the profile threshold of 10 years \(harvest-now-decrypt-later exposure for quantum-vulnerable key establishment\); declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: algorithm: observed classical; rule profile-classical: Declared crypto profile "classical" selects quantum-vulnerable key establishment and authentication; acceptable for now, with PQ migration planning required. |
| dependency | Application code paths that read this cryptographic setting; Lab evidence: 4 policy-compliant matrix row\(s\) demonstrate quantum-resistant key establishment, first row 6 \(hybrid-only / hybrid\); Lab evidence: 2 policy-compliant matrix row\(s\) demonstrate post-quantum authentication, first row 12 \(pqc-only / pqc\) |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Switch the declared profile to hybrid in a test deployment and run the interoperability matrix
- Keep the profile configurable so the switch needs no application code change

### cfg-f96a3452860e2c32ee6f6182

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | X25519 / X25519 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_group: observed X25519; rule grp-x25519: Classical key establishment; quantum-vulnerable and a harvest-now-decrypt-later planning factor for long-lived confidential traffic. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Run the matrix with X25519MLKEM768 pinned and confirm the endpoint does not fall back to X25519 |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test X25519MLKEM768 hybrid key establishment with this endpoint's clients
- Pin the required group in tests to detect silent fallback

### cfg-fc12a21d2277eb7e20e56f70

| Field | Value |
|---|---|
| priority | SHORT\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | secp384r1 / secp384r1 |
| evidence_status | complete |
| reason | Priority SHORT\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default; escalated to SHORT\_TERM \(escalation capped at SHORT\_TERM\) because declared system lifetime of 15 years meets the profile threshold of 15 years. Evidence: configured\_group: observed secp384r1; rule grp-nist-ec: Classical elliptic-curve key establishment; quantum-vulnerable and a harvest-now-decrypt-later planning factor for long-lived confidential traffic. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Test SecP256r1MLKEM768 or SecP384r1MLKEM1024 hybrid key establishment where supported
- Pin the required group in tests to detect silent fallback

### cfg-05fab0f40ee1b997cd0f246f

| Field | Value |
|---|---|
| priority | MEDIUM\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | TLSv1.2 |
| evidence_status | complete |
| reason | Priority MEDIUM\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default. Evidence: tls\_version: observed TLSv1.2; rule tls1.2: Permitted, but the hybrid and ML-KEM key-establishment groups tested in this lab require TLS 1.3. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Enable TLS 1.3 and confirm every client negotiates it
- Keep TLS 1.2 only for clients documented as unable to upgrade

### cfg-25d8e9880427c7cf37d21ca1

| Field | Value |
|---|---|
| priority | MEDIUM\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | TLSv1.2 |
| evidence_status | complete |
| reason | Priority MEDIUM\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default. Evidence: tls\_version: observed TLSv1.2; rule tls1.2: Permitted, but the hybrid and ML-KEM key-establishment groups tested in this lab require TLS 1.3. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Enable TLS 1.3 and confirm every client negotiates it
- Keep TLS 1.2 only for clients documented as unable to upgrade

### cfg-34eef6e45b87976217490b30

| Field | Value |
|---|---|
| priority | MEDIUM\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | TLSv1.2 |
| evidence_status | complete |
| reason | Priority MEDIUM\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default. Evidence: tls\_version: observed TLSv1.2; rule tls1.2: Permitted, but the hybrid and ML-KEM key-establishment groups tested in this lab require TLS 1.3. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Enable TLS 1.3 and confirm every client negotiates it
- Keep TLS 1.2 only for clients documented as unable to upgrade

### cfg-520b35adf88530aaf557656e

| Field | Value |
|---|---|
| priority | MEDIUM\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | TLSv1.2 |
| evidence_status | complete |
| reason | Priority MEDIUM\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default. Evidence: tls\_version: observed TLSv1.2; rule tls1.2: Permitted, but the hybrid and ML-KEM key-establishment groups tested in this lab require TLS 1.3. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Enable TLS 1.3 and confirm every client negotiates it
- Keep TLS 1.2 only for clients documented as unable to upgrade

### cfg-6477f32d02ac2f33f0def3a7

| Field | Value |
|---|---|
| priority | MEDIUM\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | TLSv1.2 |
| evidence_status | complete |
| reason | Priority MEDIUM\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default. Evidence: tls\_version: observed TLSv1.2; rule tls1.2: Permitted, but the hybrid and ML-KEM key-establishment groups tested in this lab require TLS 1.3. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Enable TLS 1.3 and confirm every client negotiates it
- Keep TLS 1.2 only for clients documented as unable to upgrade

### cfg-7d081946612253cdbe8b698d

| Field | Value |
|---|---|
| priority | MEDIUM\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | TLSv1.2 |
| evidence_status | complete |
| reason | Priority MEDIUM\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default. Evidence: tls\_version: observed TLSv1.2; rule tls1.2: Permitted, but the hybrid and ML-KEM key-establishment groups tested in this lab require TLS 1.3. |
| dependency | Every process that loads this OpenSSL configuration |
| recommended_test | Load the configuration in an isolated test process and list the effective groups and algorithms |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Enable TLS 1.3 and confirm every client negotiates it
- Keep TLS 1.2 only for clients documented as unable to upgrade

### cfg-b57c730872980f8c7c560028

| Field | Value |
|---|---|
| priority | MEDIUM\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | TLSv1.2 |
| evidence_status | complete |
| reason | Priority MEDIUM\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default. Evidence: tls\_version: observed TLSv1.2; rule tls1.2: Permitted, but the hybrid and ML-KEM key-establishment groups tested in this lab require TLS 1.3. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Enable TLS 1.3 and confirm every client negotiates it
- Keep TLS 1.2 only for clients documented as unable to upgrade

### cfg-d36ab6e62bb470f042ddd29d

| Field | Value |
|---|---|
| priority | MEDIUM\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | TLSv1.2 |
| evidence_status | complete |
| reason | Priority MEDIUM\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default. Evidence: tls\_version: observed TLSv1.2; rule tls1.2: Permitted, but the hybrid and ML-KEM key-establishment groups tested in this lab require TLS 1.3. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Enable TLS 1.3 and confirm every client negotiates it
- Keep TLS 1.2 only for clients documented as unable to upgrade

### cfg-ee64e5ecb2de01dcfb234b18

| Field | Value |
|---|---|
| priority | MEDIUM\_TERM |
| outcome | ACCEPTABLE\_FOR\_NOW |
| current_algorithm | TLSv1.2 |
| evidence_status | complete |
| reason | Priority MEDIUM\_TERM: outcome ACCEPTABLE\_FOR\_NOW maps to MEDIUM\_TERM under policy default. Evidence: tls\_version: observed TLSv1.2; rule tls1.2: Permitted, but the hybrid and ML-KEM key-establishment groups tested in this lab require TLS 1.3. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Schedule PQ migration planning and add the target profile to the lab test matrix. |

Migration options:

- Enable TLS 1.3 and confirm every client negotiates it
- Keep TLS 1.2 only for clients documented as unable to upgrade

### cert-cc93ba704f7ab337985f8f71

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | EXPERIMENTAL |
| current_algorithm | ML-DSA-65 / ML-DSA-65 |
| evidence_status | complete |
| reason | Priority MONITOR: outcome EXPERIMENTAL maps to MONITOR under policy default. Evidence: algorithm: certificate context; rule ml-dsa: PQ X.509 certificate profiles are treated as laboratory interoperability experiments; FIPS 204 standardizes the algorithm, not every certificate or client implementation. |
| dependency | Issuing CA signature profile and every relying party's trust store and certificate parser |
| recommended_test | Issue a synthetic certificate with the target key and signature algorithm and verify chain validation in each client used with this certificate |
| blocker | - |
| next_action | Keep in the lab; track interoperability results before any production decision. |

Migration options:

- No algorithm change required; verify chain validation in every relying client
- Keep a classical certificate path available until client support is verified
- Verify chain validation and handshake behaviour in every relying client

### cfg-040db8578ae6d4e03461c95a

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | APPROVED |
| current_algorithm | TLS\_AES\_128\_GCM\_SHA256 |
| evidence_status | complete |
| reason | Priority MONITOR: outcome APPROVED maps to MONITOR under policy default. Evidence: cipher\_suite: observed TLS\_AES\_128\_GCM\_SHA256; rule cs-tls13-aead: TLS 1.3 AEAD cipher suite approved by this policy. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Monitor; re-evaluate when the policy or the asset changes. |

Migration options:

- No cipher suite change required

### cfg-08635a3fed651474ad230150

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | EXPERIMENTAL |
| current_algorithm | X25519MLKEM768 / X25519MLKEM768 |
| evidence_status | complete |
| reason | Priority MONITOR: outcome EXPERIMENTAL maps to MONITOR under policy default. Evidence: configured\_group: observed X25519MLKEM768; rule grp-hybrid-x25519-mlkem768: Hybrid X25519 plus ML-KEM-768 key establishment. ML-KEM is standardized; this policy treats the TLS hybrid group integration as a laboratory experiment. Reference: NIST FIPS 203 \(ML-KEM component\). |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Keep in the lab; track interoperability results before any production decision. |

Migration options:

- Keep a pinned-group regression test so fallback to a classical group is detected
- Measure handshake size impact on constrained links

### cfg-0ca58929ff7dcd3d597bfad1

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | APPROVED |
| current_algorithm | TLS\_AES\_256\_GCM\_SHA384 |
| evidence_status | complete |
| reason | Priority MONITOR: outcome APPROVED maps to MONITOR under policy default. Evidence: cipher\_suite: observed TLS\_AES\_256\_GCM\_SHA384; rule cs-tls13-aead: TLS 1.3 AEAD cipher suite approved by this policy. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Monitor; re-evaluate when the policy or the asset changes. |

Migration options:

- No cipher suite change required

### cfg-13f3757b759d1b51f54db3a9

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | APPROVED |
| current_algorithm | TLS\_AES\_128\_GCM\_SHA256 |
| evidence_status | complete |
| reason | Priority MONITOR: outcome APPROVED maps to MONITOR under policy default. Evidence: cipher\_suite: observed TLS\_AES\_128\_GCM\_SHA256; rule cs-tls13-aead: TLS 1.3 AEAD cipher suite approved by this policy. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Monitor; re-evaluate when the policy or the asset changes. |

Migration options:

- No cipher suite change required

### cfg-1aed3eaccb7ec20a013f13bd

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | APPROVED |
| current_algorithm | TLS\_AES\_128\_GCM\_SHA256 |
| evidence_status | complete |
| reason | Priority MONITOR: outcome APPROVED maps to MONITOR under policy default. Evidence: cipher\_suite: observed TLS\_AES\_128\_GCM\_SHA256; rule cs-tls13-aead: TLS 1.3 AEAD cipher suite approved by this policy. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Monitor; re-evaluate when the policy or the asset changes. |

Migration options:

- No cipher suite change required

### cfg-2f505116b71eb4ef65d6bcf3

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | APPROVED |
| current_algorithm | AES-128-GCM |
| evidence_status | complete |
| reason | Priority MONITOR: outcome APPROVED maps to MONITOR under policy default. Evidence: cipher\_suite: observed AES-128-GCM; rule cs-aead-generic: AEAD symmetric cipher permitted by this policy; symmetric ciphers are not the public-key migration target of this lab. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Monitor; re-evaluate when the policy or the asset changes. |

Migration options:

- No cipher change required

### cfg-3b96a65e25026be67cfea50f

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | APPROVED |
| current_algorithm | TLS\_AES\_128\_GCM\_SHA256 |
| evidence_status | complete |
| reason | Priority MONITOR: outcome APPROVED maps to MONITOR under policy default. Evidence: cipher\_suite: observed TLS\_AES\_128\_GCM\_SHA256; rule cs-tls13-aead: TLS 1.3 AEAD cipher suite approved by this policy. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Monitor; re-evaluate when the policy or the asset changes. |

Migration options:

- No cipher suite change required

### cfg-3d73eed04502597bd3ece140

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | EXPERIMENTAL |
| current_algorithm | X25519MLKEM768 / X25519MLKEM768 |
| evidence_status | complete |
| reason | Priority MONITOR: outcome EXPERIMENTAL maps to MONITOR under policy default. Evidence: configured\_group: observed X25519MLKEM768; rule grp-hybrid-x25519-mlkem768: Hybrid X25519 plus ML-KEM-768 key establishment. ML-KEM is standardized; this policy treats the TLS hybrid group integration as a laboratory experiment. Reference: NIST FIPS 203 \(ML-KEM component\). |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Keep in the lab; track interoperability results before any production decision. |

Migration options:

- Keep a pinned-group regression test so fallback to a classical group is detected
- Measure handshake size impact on constrained links

### cfg-3f44cc1fcc713ff8adb1eda5

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | APPROVED |
| current_algorithm | TLSv1.3 |
| evidence_status | complete |
| reason | Priority MONITOR: outcome APPROVED maps to MONITOR under policy default. Evidence: tls\_version: observed TLSv1.3; rule tls1.3: Protocol version approved by this policy and required for the PQ groups tested in this lab. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Monitor; re-evaluate when the policy or the asset changes. |

Migration options:

- No protocol version change required

### cfg-3f734a49baacf8704a5bef59

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | APPROVED |
| current_algorithm | AES-256-GCM |
| evidence_status | complete |
| reason | Priority MONITOR: outcome APPROVED maps to MONITOR under policy default. Evidence: cipher\_suite: observed AES-256-GCM; rule cs-aead-generic: AEAD symmetric cipher permitted by this policy; symmetric ciphers are not the public-key migration target of this lab. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Monitor; re-evaluate when the policy or the asset changes. |

Migration options:

- No cipher change required

### cfg-4c1296bece5dab27d04084ac

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | APPROVED |
| current_algorithm | TLS\_AES\_128\_GCM\_SHA256 |
| evidence_status | complete |
| reason | Priority MONITOR: outcome APPROVED maps to MONITOR under policy default. Evidence: cipher\_suite: observed TLS\_AES\_128\_GCM\_SHA256; rule cs-tls13-aead: TLS 1.3 AEAD cipher suite approved by this policy. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Monitor; re-evaluate when the policy or the asset changes. |

Migration options:

- No cipher suite change required

### cfg-55ddefdf8b561c08d9459def

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | APPROVED |
| current_algorithm | AES-256-GCM |
| evidence_status | complete |
| reason | Priority MONITOR: outcome APPROVED maps to MONITOR under policy default. Evidence: cipher\_suite: observed AES-256-GCM; rule cs-aead-generic: AEAD symmetric cipher permitted by this policy; symmetric ciphers are not the public-key migration target of this lab. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Monitor; re-evaluate when the policy or the asset changes. |

Migration options:

- No cipher change required

### cfg-55fb9809fe402b5c2af9bdfe

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | EXPERIMENTAL |
| current_algorithm | hybrid |
| evidence_status | complete |
| reason | Priority MONITOR: outcome EXPERIMENTAL maps to MONITOR under policy default. Evidence: algorithm: observed hybrid; rule profile-hybrid: Declared crypto profile "hybrid" combines classical and ML-KEM key establishment; the TLS hybrid group integration is treated as a laboratory experiment. Authentication may still be classical. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Keep in the lab; track interoperability results before any production decision. |

Migration options:

- Keep a pinned-group regression test so fallback to a classical group is detected
- Track the remaining classical authentication dependency separately

### cfg-561d7ca5815ce6b493a768c6

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | APPROVED |
| current_algorithm | TLS\_AES\_128\_GCM\_SHA256 |
| evidence_status | complete |
| reason | Priority MONITOR: outcome APPROVED maps to MONITOR under policy default. Evidence: cipher\_suite: observed TLS\_AES\_128\_GCM\_SHA256; rule cs-tls13-aead: TLS 1.3 AEAD cipher suite approved by this policy. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Monitor; re-evaluate when the policy or the asset changes. |

Migration options:

- No cipher suite change required

### cfg-5dfbd6b100beaff82616437e

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | APPROVED |
| current_algorithm | TLS\_AES\_256\_GCM\_SHA384 |
| evidence_status | complete |
| reason | Priority MONITOR: outcome APPROVED maps to MONITOR under policy default. Evidence: cipher\_suite: observed TLS\_AES\_256\_GCM\_SHA384; rule cs-tls13-aead: TLS 1.3 AEAD cipher suite approved by this policy. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Monitor; re-evaluate when the policy or the asset changes. |

Migration options:

- No cipher suite change required

### cfg-624cec9c08f076441d8cf887

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | APPROVED |
| current_algorithm | TLS\_AES\_128\_GCM\_SHA256 |
| evidence_status | complete |
| reason | Priority MONITOR: outcome APPROVED maps to MONITOR under policy default. Evidence: cipher\_suite: observed TLS\_AES\_128\_GCM\_SHA256; rule cs-tls13-aead: TLS 1.3 AEAD cipher suite approved by this policy. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Monitor; re-evaluate when the policy or the asset changes. |

Migration options:

- No cipher suite change required

### cfg-65e8654e3892d1347c44b818

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | APPROVED |
| current_algorithm | TLS\_AES\_128\_GCM\_SHA256 |
| evidence_status | complete |
| reason | Priority MONITOR: outcome APPROVED maps to MONITOR under policy default. Evidence: cipher\_suite: observed TLS\_AES\_128\_GCM\_SHA256; rule cs-tls13-aead: TLS 1.3 AEAD cipher suite approved by this policy. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Monitor; re-evaluate when the policy or the asset changes. |

Migration options:

- No cipher suite change required

### cfg-6a562c2cf515a0e16de5645a

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | APPROVED |
| current_algorithm | TLSv1.3 |
| evidence_status | complete |
| reason | Priority MONITOR: outcome APPROVED maps to MONITOR under policy default. Evidence: tls\_version: observed TLSv1.3; rule tls1.3: Protocol version approved by this policy and required for the PQ groups tested in this lab. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Monitor; re-evaluate when the policy or the asset changes. |

Migration options:

- No protocol version change required

### cfg-77486bda33a5bfd5c6a5dff0

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | APPROVED |
| current_algorithm | TLS\_AES\_256\_GCM\_SHA384 |
| evidence_status | complete |
| reason | Priority MONITOR: outcome APPROVED maps to MONITOR under policy default. Evidence: cipher\_suite: observed TLS\_AES\_256\_GCM\_SHA384; rule cs-tls13-aead: TLS 1.3 AEAD cipher suite approved by this policy. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Monitor; re-evaluate when the policy or the asset changes. |

Migration options:

- No cipher suite change required

### cfg-81a0a45f57c63044aee01559

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | APPROVED |
| current_algorithm | TLSv1.3 |
| evidence_status | complete |
| reason | Priority MONITOR: outcome APPROVED maps to MONITOR under policy default. Evidence: tls\_version: observed TLSv1.3; rule tls1.3: Protocol version approved by this policy and required for the PQ groups tested in this lab. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Monitor; re-evaluate when the policy or the asset changes. |

Migration options:

- No protocol version change required

### cfg-8feb80d2d5734e0b33ad8df3

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | EXPERIMENTAL |
| current_algorithm | MLKEM768 / MLKEM768 |
| evidence_status | complete |
| reason | Priority MONITOR: outcome EXPERIMENTAL maps to MONITOR under policy default. Evidence: configured\_group: observed MLKEM768; rule grp-mlkem: Pure ML-KEM key establishment without a classical component. ML-KEM is standardized; this policy treats the pure-PQ TLS group integration as a laboratory experiment. Reference: NIST FIPS 203. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Keep in the lab; track interoperability results before any production decision. |

Migration options:

- Confirm every client supports the group before relying on it
- Compare with a hybrid group during the transition

### cfg-942c9c8e8cf64aae82d59ea1

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | APPROVED |
| current_algorithm | AES-256-GCM |
| evidence_status | complete |
| reason | Priority MONITOR: outcome APPROVED maps to MONITOR under policy default. Evidence: cipher\_suite: observed AES-256-GCM; rule cs-aead-generic: AEAD symmetric cipher permitted by this policy; symmetric ciphers are not the public-key migration target of this lab. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Monitor; re-evaluate when the policy or the asset changes. |

Migration options:

- No cipher change required

### cfg-94652e95084f7720c9313a26

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | EXPERIMENTAL |
| current_algorithm | hybrid |
| evidence_status | complete |
| reason | Priority MONITOR: outcome EXPERIMENTAL maps to MONITOR under policy default. Evidence: algorithm: observed hybrid; rule profile-hybrid: Declared crypto profile "hybrid" combines classical and ML-KEM key establishment; the TLS hybrid group integration is treated as a laboratory experiment. Authentication may still be classical. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Keep in the lab; track interoperability results before any production decision. |

Migration options:

- Keep a pinned-group regression test so fallback to a classical group is detected
- Track the remaining classical authentication dependency separately

### cfg-9c2498f6d81965d545b71f9f

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | EXPERIMENTAL |
| current_algorithm | mldsa65 |
| evidence_status | complete |
| reason | Priority MONITOR: outcome EXPERIMENTAL maps to MONITOR under policy default. Evidence: configured\_signature: observed mldsa65; rule sig-ml-dsa: Standardized PQ signature algorithm used in an X.509 certificate; this policy treats PQ certificate profiles as laboratory interoperability experiments. Reference: NIST FIPS 204. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Keep in the lab; track interoperability results before any production decision. |

Migration options:

- Verify chain validation and handshake behaviour in every relying client
- Keep a classical certificate path available until client support is verified

### cfg-9f4e9e198068f6b7498f6af0

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | APPROVED |
| current_algorithm | TLS\_AES\_256\_GCM\_SHA384 |
| evidence_status | complete |
| reason | Priority MONITOR: outcome APPROVED maps to MONITOR under policy default. Evidence: cipher\_suite: observed TLS\_AES\_256\_GCM\_SHA384; rule cs-tls13-aead: TLS 1.3 AEAD cipher suite approved by this policy. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Monitor; re-evaluate when the policy or the asset changes. |

Migration options:

- No cipher suite change required

### cfg-a3d81e4d32deb21beb8285cb

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | APPROVED |
| current_algorithm | TLS\_AES\_128\_GCM\_SHA256 |
| evidence_status | complete |
| reason | Priority MONITOR: outcome APPROVED maps to MONITOR under policy default. Evidence: cipher\_suite: observed TLS\_AES\_128\_GCM\_SHA256; rule cs-tls13-aead: TLS 1.3 AEAD cipher suite approved by this policy. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Monitor; re-evaluate when the policy or the asset changes. |

Migration options:

- No cipher suite change required

### cfg-aaa05e61b362f08889b8eab8

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | APPROVED |
| current_algorithm | AES-256-GCM |
| evidence_status | complete |
| reason | Priority MONITOR: outcome APPROVED maps to MONITOR under policy default. Evidence: cipher\_suite: observed AES-256-GCM; rule cs-aead-generic: AEAD symmetric cipher permitted by this policy; symmetric ciphers are not the public-key migration target of this lab. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Monitor; re-evaluate when the policy or the asset changes. |

Migration options:

- No cipher change required

### cfg-d3bc277f50ff6a1471635139

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | APPROVED |
| current_algorithm | TLS\_AES\_128\_GCM\_SHA256 |
| evidence_status | complete |
| reason | Priority MONITOR: outcome APPROVED maps to MONITOR under policy default. Evidence: cipher\_suite: observed TLS\_AES\_128\_GCM\_SHA256; rule cs-tls13-aead: TLS 1.3 AEAD cipher suite approved by this policy. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Monitor; re-evaluate when the policy or the asset changes. |

Migration options:

- No cipher suite change required

### cfg-d43a18db57cb8ce16cc6abdb

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | APPROVED |
| current_algorithm | TLS\_AES\_128\_GCM\_SHA256 |
| evidence_status | complete |
| reason | Priority MONITOR: outcome APPROVED maps to MONITOR under policy default. Evidence: cipher\_suite: observed TLS\_AES\_128\_GCM\_SHA256; rule cs-tls13-aead: TLS 1.3 AEAD cipher suite approved by this policy. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Monitor; re-evaluate when the policy or the asset changes. |

Migration options:

- No cipher suite change required

### cfg-d64beebfcf1289aba8fd4405

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | APPROVED |
| current_algorithm | TLS\_AES\_128\_GCM\_SHA256 |
| evidence_status | complete |
| reason | Priority MONITOR: outcome APPROVED maps to MONITOR under policy default. Evidence: cipher\_suite: observed TLS\_AES\_128\_GCM\_SHA256; rule cs-tls13-aead: TLS 1.3 AEAD cipher suite approved by this policy. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Monitor; re-evaluate when the policy or the asset changes. |

Migration options:

- No cipher suite change required

### cfg-d9f0699b5188a3a55648a2da

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | APPROVED |
| current_algorithm | TLSv1.3 |
| evidence_status | complete |
| reason | Priority MONITOR: outcome APPROVED maps to MONITOR under policy default. Evidence: tls\_version: observed TLSv1.3; rule tls1.3: Protocol version approved by this policy and required for the PQ groups tested in this lab. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Monitor; re-evaluate when the policy or the asset changes. |

Migration options:

- No protocol version change required

### cfg-e1ae031c09f6053bd7902312

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | APPROVED |
| current_algorithm | TLSv1.3 |
| evidence_status | complete |
| reason | Priority MONITOR: outcome APPROVED maps to MONITOR under policy default. Evidence: tls\_version: observed TLSv1.3; rule tls1.3: Protocol version approved by this policy and required for the PQ groups tested in this lab. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Monitor; re-evaluate when the policy or the asset changes. |

Migration options:

- No protocol version change required

### cfg-e4aa836823f336f9418d55ab

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | APPROVED |
| current_algorithm | AES-256-GCM |
| evidence_status | complete |
| reason | Priority MONITOR: outcome APPROVED maps to MONITOR under policy default. Evidence: cipher\_suite: observed AES-256-GCM; rule cs-aead-generic: AEAD symmetric cipher permitted by this policy; symmetric ciphers are not the public-key migration target of this lab. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Monitor; re-evaluate when the policy or the asset changes. |

Migration options:

- No cipher change required

### cfg-edc3ee29cebfed36a3f41641

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | APPROVED |
| current_algorithm | TLS\_AES\_256\_GCM\_SHA384 |
| evidence_status | complete |
| reason | Priority MONITOR: outcome APPROVED maps to MONITOR under policy default. Evidence: cipher\_suite: observed TLS\_AES\_256\_GCM\_SHA384; rule cs-tls13-aead: TLS 1.3 AEAD cipher suite approved by this policy. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Monitor; re-evaluate when the policy or the asset changes. |

Migration options:

- No cipher suite change required

### cfg-ee29a3cb189e6be4d2c223f3

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | APPROVED |
| current_algorithm | AES-256-GCM |
| evidence_status | complete |
| reason | Priority MONITOR: outcome APPROVED maps to MONITOR under policy default. Evidence: cipher\_suite: observed AES-256-GCM; rule cs-aead-generic: AEAD symmetric cipher permitted by this policy; symmetric ciphers are not the public-key migration target of this lab. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Monitor; re-evaluate when the policy or the asset changes. |

Migration options:

- No cipher change required

### cfg-eebd002e538f7540f983fc46

| Field | Value |
|---|---|
| priority | MONITOR |
| outcome | EXPERIMENTAL |
| current_algorithm | pqc |
| evidence_status | complete |
| reason | Priority MONITOR: outcome EXPERIMENTAL maps to MONITOR under policy default. Evidence: algorithm: observed pqc; rule profile-pqc: Declared crypto profile "pqc" uses ML-KEM key establishment and PQ authentication; treated as a laboratory experiment until every client is verified. |
| dependency | Application code paths that read this cryptographic setting |
| recommended_test | Switch the configured profile in a test deployment and run the application's test suite |
| blocker | - |
| next_action | Keep in the lab; track interoperability results before any production decision. |

Migration options:

- Confirm every client supports the profile before relying on it
- Keep a hybrid fallback profile available and explicitly selected, never silent

### cfg-7f2318daf340ae581fe10472

| Field | Value |
|---|---|
| priority | UNKNOWN |
| outcome | UNSUPPORTED |
| current_algorithm | unrecognized |
| evidence_status | unrecognized |
| reason | Priority UNKNOWN: evidence is unrecognized; the policy fails closed and no migration priority can be assigned until evidence is complete. Evidence: algorithm: algorithm unrecognized is not recognised by this policy. Evidence is missing, unrecognised or conflicting, so this policy cannot classify the dependency and fails closed. |
| dependency | Every process that loads this OpenSSL configuration |
| recommended_test | Re-run inventory discovery on the asset and confirm every required field is recorded |
| blocker | Evidence gap: algorithm: algorithm unrecognized is not recognised by this policy. Evidence is missing, unrecognised or conflicting, so this policy cannot classify the dependency and fails closed. |
| next_action | Complete inventory evidence for this asset before any migration decision. |

Migration options:

- Re-run explicit discovery to record the missing algorithm, parameter or protocol evidence
- Add a reviewed policy rule if the dependency is legitimate but not yet covered
