# Interoperability

Detail behind the [README interoperability summary](../README.md#interoperability):
byte-for-byte parity with OpenSSL's own default-provider ML-DSA, and cross-
implementation interop against the wider PQC ecosystem. All of this is exercised
by the test suite (`interop`, `ietf_interop`, `kat`, `tls` — see the
[README Test section](../README.md#test)).

## With the OpenSSL default provider

Verified by the test suite and byte-for-byte against OpenSSL 3.5's default
provider:

- **Seed-expansion parity** — importing the same 32-byte seed into both
  providers yields the identical public key.
- **Cross sign/verify** — a signature produced by one provider verifies with
  the other, in both directions (pure ML-DSA, empty context).
- **Key-file formats** — public keys as `SubjectPublicKeyInfo` (raw key in the
  BIT STRING) and private keys as PKCS#8 in the default provider's `seed-priv`
  form: `privateKey OCTET STRING { SEQUENCE { OCTET STRING seed(32),
  OCTET STRING expandedKey } }`. PEM/DER written by one side is read by the
  other; the DER is byte-identical in shape to the default provider's.
- **Known-answer tests** — deterministic keygen and signing reproduce the
  FIPS 204 test vectors shipped with mldsa-native.

## Cross-implementation interop (IETF pqc-certificates)

The `ietf_interop` test consumes the ML-DSA artifacts published by many
independent implementations at
[IETF-Hackathon/pqc-certificates](https://github.com/IETF-Hackathon/pqc-certificates)
and, using **only this provider** for the ML-DSA operations, checks that each
implementation's self-signed trust-anchor certificate verifies and that every
private-key form they ship (`seed` / `expandedKey` / `both`) loads and signs.
It currently passes against **7 implementations** (bc, botan, carl-redhound,
openjdk, ossl35, safelogic, sanctum-secops) across all three levels — **117
checks, on both OpenSSL 3.4 and 3.5**. Because this provider now supplies the
X.509 machinery for ML-DSA below 3.5 (OID/sigid registration + SPKI/PKCS#8
codecs), the test no longer needs a 3.5 core; it self-skips only without network
access or if the provider cannot be loaded.
