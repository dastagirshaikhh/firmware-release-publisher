# Firmware Release Publisher

The firmware code-signing key was rotated. Since the rotation, release bundles submitted to the distribution gateway are being rejected with an `UNTRUSTED_SIGNATURE` error because the publisher has not been updated to sign with the active key. Implement a new publisher that reconciles the manifest and successfully publishes the releases.

## Deliverable

Implement the release publisher in `/app/publisher/release-publisher.mjs`. The program is executed using `npm run report`, which runs the publisher in report mode.

## Environment

The following resources are available in the container:

- `/app/fixtures/build_manifest.csv` (raw build manifest).
- `/app/reports/publications.expected.txt` (expected deterministic report format).
- `/app/distribution-gateway/` (provided HTTP distribution gateway).
- `/app/keys/current/current.key.pem` (current private signing key).
- `/app/keys/current/current.cert.pem` (current signing certificate).
- `/app/keys/revoked/revoked.key.pem` (revoked private key).
- `/app/keys/revoked/revoked.cert.pem` (revoked certificate).
- `/app/package.json` (package configuration and report command).

## Manifest Schema

The manifest columns are `entry_id`, `bundle_id`, `component_id`, `version`, `size_bytes`, `record_type`, `supersedes_id` and `recorded_at`.

`record_type` is either `BUILD` or `WITHDRAWAL`. For a withdrawal record, `supersedes_id` identifies the exact `entry_id` of the build which is cancelled.

## Manifest Reconciliation

Manifest data should be reconciled using SQL before publishing. If multiple manifest rows are identical across every column, treat them as a single record. A `WITHDRAWAL` cancels the `BUILD` whose `entry_id` is referenced by `supersedes_id`. After duplicate removal and withdrawals are applied, a bundle is publishable only if at least one build remains. If every build in a bundle is withdrawn that bundle must not be published. For each publishable bundle, calculate `artifact_count`, the number of surviving `BUILD` rows and `total_bytes` the sum of `size_bytes` of the surviving rows. Process publishable bundles in ascending `bundle_id` order.

## Signing

For each publishable bundle, generate a signed descriptor. Each signed descriptor must contain exactly the fields `artifact_count`, `bundle_id` and `total_bytes`. The descriptor must be canonical JSON with UTF-8 encoding, lexicographically sorted keys and no unnecessary whitespace. The exact bytes signed must be the exact same bytes submitted to the gateway. The gateway expects the release descriptor to be signed using OpenSSL CMS. The publisher must use the currently active signing key and certificate indicated by the gateway. The revoked signing key must not be used.

The current signing-key information is available from `GET http://127.0.0.1:7070/v1/signing-key/current`

## Distribution Gateway

The gateway runs locally at `http://127.0.0.1:7070`.
The gateway's base URL is `http://127.0.0.1:7070` by default. If the GATEWAY_URL environment variable is set, the publisher must use it instead.
`GET http://127.0.0.1:7070/v1/signing-key/current` returns the current `key_id`, algorithm, certificate reference and status.
`POST http://127.0.0.1:7070/v1/publications` accepts a request containing `descriptor`, `signature` and `request_token`.
A successful publication response contains `publication_id`, `request_token` and `status` set to `PUBLISHED`.

Interact with the distribution gateway only through its documented HTTP API. Do not read or write the gateway's private internal storage. Do not modify the provided distribution gateway or its implementation.

## Persistence and Idempotency

Create a database at `/app/releases.duckdb` at runtime. The database must persist enough information to allow the publisher to recognize already-published bundles and reuse their stored results.

The deterministic request token must be exactly `token-<bundle_id>`.

If the publisher runs again with the same manifest, it must not create duplicate publications and repeated runs must produce byte-identical report output.

## Required Output

For each publishable bundle, output exactly two lines in ascending `bundle_id` order

```text
BUNDLE <bundle_id> SIGNED KEY=<key_id>
BUNDLE <bundle_id> PUBLISHED RECEIPT=<publication_id> TOKEN=<request_token> STATUS=PUBLISHED
```

The `key_id` must come directly from the gateway's current-signing-key response. The request token must follow the `token-<bundle_id>` format.

## Definition of Done

The implementation is complete when:
All publishable bundles are correctly reconciled. Fully withdrawn bundles are omitted. Duplicate rows are handled correctly. Every publishable bundle is successfully signed with the current key. Publications are accepted by the gateway. Publication state is stored in DuckDB. Request tokens are deterministic. Rerunning skips creation of duplicate publications. Report output is deterministic and correctly formatted.
