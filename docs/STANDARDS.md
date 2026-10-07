# Standards and implementation references

Authoritative documentation checked before implementation:

- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final): ML-KEM, a key encapsulation mechanism;
  parameter sets ML-KEM-512, ML-KEM-768, ML-KEM-1024.
- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final): ML-DSA signatures;
  parameter sets ML-DSA-44, ML-DSA-65, ML-DSA-87.
- [NIST FIPS 205](https://csrc.nist.gov/pubs/fips/205/final): SLH-DSA signatures,
  SHA2/SHAKE families with standardized parameter sets.
- [OpenSSL releases](https://openssl-library.org/source/): OpenSSL 3.5.9 LTS pinned with published SHA-256;
  the system installation is not replaced.
- [Native ML-KEM](https://docs.openssl.org/3.5/man7/EVP_KEM-ML-KEM/),
  [ML-DSA](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/),
  [SLH-DSA](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-SLH-DSA/): native support added in 3.5.
- [TLS groups and negotiation](https://docs.openssl.org/3.5/man3/SSL_CTX_set1_groups/):
  query with `openssl list -tls1_3 -tls-groups`; pin a single required group to avoid fallback.

Main documentation uses standardized algorithm names, not historical submission names.
The default provider is an established implementation, not a claim of FIPS 140 validation.
TLS integrations and PQ X.509 interoperability are laboratory experiments. Final protocol
standardization and algorithm standardization are separate claims. No oqs-provider or liboqs
is necessary for the core native experiments; unsupported combinations must be reported honestly.
