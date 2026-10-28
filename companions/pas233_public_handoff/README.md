# Public handoff companion

This standard-library Python module checks bounded public candidate declarations for consistency with separately supplied review facts. It reports missing fields and rejects malformed references, substituted hashes, unsupported scope, incomplete provenance, caller-supplied status and unexpected fields.

Every result is `NONEXECUTING`. `execution_authorized`, `operational_trust_verified` and `owner_schema_acknowledged` remain false, including for a `CONSISTENT` result. Matching two untrusted inputs does not authenticate either input.

## Interface

`validate(candidate_raw, review_reference_raw=None)` accepts JSON bytes, each limited to 32,768 bytes. It returns fixed diagnostic codes and schema field names without echoing supplied values or unknown keys. `missing_input_handoff()` lists the unresolved real public inputs and integration gates.

Candidate fields are exactly `schema`, `scope`, `channel`, `binding`, `status_source` and `provenance`. The companion envelope is proposed metadata for source-owner review, not an accepted runtime input format. The JSON fixtures demonstrate its complete shape using documentation-only addresses, `.invalid` hosts and fabricated digests. They contain no key or credential material.

The observed UNIT v2 channel has exact fields `schema`, `issuer`, `public_key_path`, `public_key_sha256`, `status_url`, `status_address`, `ca_sha256` and `openssl_sha256`. Its digest uses sorted compact JSON plus a newline. Static channel data excludes action and grant hashes; action and binding declarations reference the channel digest. `public_key_sha256` refers to exact public PEM file bytes. This module never reads the referenced files.

The proposed status descriptor identifies the required signed status source; it is not a status response or authentication result. Installation-authority roles and historical staging receipts do not establish UNIT or PG execution scope. PG remains rejected until a separate accepted contract is supplied.

HTTPS reference checks reject credentials, queries, malformed escapes and malformed hosts. Status URLs also reject fragments; evidence URLs may retain public anchors. These are syntax checks, without DNS resolution, endpoint authentication or a trust allowlist.

## Tests

From the repository root:

```sh
python3 -B -m unittest discover -s tests -p 'test_public_handoff*.py' -v
python3 -B -O -m unittest discover -s tests -p 'test_public_handoff*.py' -v
```

The 38 tests run through the repository's existing unittest discovery. They cover positive synthetic candidates, every required field, malformed types and references, exact hash linkage, provenance conflicts, scope separation, byte bounds, duplicate/deep JSON, deterministic output and non-disclosure. Regression cases include numeric overflow and malformed URLs that agree across candidate and review inputs.

## Integration status

The source owner must accept the companion envelope and syntax checks and reconcile them with the final immutable runtime package. The recorded upstream API observations are historical hashes; the runtime source has changed since those observations. This companion does not claim compatibility with the current moving source.

`OWNER_HANDSHAKE_INTEGRATION_REQUIRED` remains present on every report. The module does not implement readiness nonces, process/machine/boot attestation, one-shot reception, action freshness, signature verification, revocation, replay exclusion or runtime containment. The existing author/issuer/reviewer workflow owns those requirements and the canonical descriptor -> action -> grant/envelope chain.

No operational keys, grants, credentials, leases, trust stores, logs or installation receipts are supplied by this companion. Final runtime integration and independent acceptance remain with the existing source owner and designated reviewer.
