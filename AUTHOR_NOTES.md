# Author Notes

## Task Design

I designed this task to simulate a real world release engineering problem where a firmware code signing key gets rotated out. The solver has to build a publisher that ingests a messy manifest, reconciles the data, signs the payload with the new active key and pushes it to an HTTP gateway. It tests the ability to combine SQL data wrangling in DuckDB with OpenSSL cryptographic tools and HTTP idempotency concepts.

## Core Requirements

One of the main things the solver has to figure out is canonical JSON formatting. The gateway verifies the detached CMS signature byte for byte, so if they do not sort the keys lexicographically or if they leave trailing whitespace, the signature breaks. They also have to generate a deterministic request token using the `token-<bundle_id>` format. The publisher persists publication receipts and request tokens in DuckDB so that a subsequent run can reuse the stored publication state instead of creating duplicate publications.

## Deliberate Traps

I built a few intentional traps into the data and the environment. The manifest contains exact duplicate rows to ensure that duplicate records are counted only once during reconciliation. There are also withdrawal records that require them to filter out superseded builds. I included a bundle that becomes fully withdrawn, requiring the publisher to omit it from the publishable set. The biggest trap is the keys directory. I left the old revoked key pair in there alongside the current one. If they just grab the first key they find or hardcode the wrong path, the gateway will reject it with an untrusted signature error.

## Grader Design

The verifier is built to recompute the expected answers instead of just trusting hardcoded values. The first test checks that the standard output matches the expected golden file with the receipt hashes masked out. The second and third tests verify that DuckDB persistence works, tokens are unique and rerunning the script does not alter the database row count or output. The fourth test dynamically calculates the expected publishable bundle set from the manifest and compares it with the bundle IDs persisted by the publisher, checking that duplicate and withdrawal handling produce the expected publishable set. The final test explicitly signs a payload with the revoked key and hits the gateway to prove the untrusted signature trap is actively enforced.

## Verification

The submission handbook requires us to prove the task is both unsolved initially and solvable with the reference code.

### Proof A (Empty Solution)

When running the tests against an empty environment where the publisher script does not exist, the verifier correctly fails. The golden output test catches the missing file and the subsequent logic tests fail because there is no DuckDB database created. The only test that passes is the revoked key trap test since that one is an independent API check. This gives an actual result of four failed tests, one passed test and a final reward of zero.

### Proof B (Reference Solution)

When injecting the reference solution into the environment and running the verifier again, all five verifier tests passed and the final reward was 1, demonstrating that the reference solution satisfies the verifier. This proves the task is solvable and the grader is accurate.
