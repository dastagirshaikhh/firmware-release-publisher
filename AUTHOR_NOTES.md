# Author Notes

## Task Design

I designed this task to simulate a real world release engineering problem where a firmware code signing key gets rotated out. The solver has to build a publisher that ingests a messy manifest, reconciles the data, signs the payload with the new active key and pushes it to an HTTP gateway. It tests the ability to combine SQL data wrangling in DuckDB with OpenSSL cryptographic tools and HTTP idempotency concepts.

## Core Requirements

One of the main things the solver has to figure out is canonical JSON formatting. The gateway verifies the detached CMS signature byte for byte, so if they do not sort the keys lexicographically or if they leave trailing whitespace, the signature breaks. They also have to generate a deterministic request token using the `token-<bundle_id>` format. The publisher persists publication receipts and request tokens in DuckDB so that a subsequent run can reuse the stored publication state instead of creating duplicate publications.

## Deliberate Traps

I built a few intentional traps into the data and the environment. The manifest contains exact duplicate rows to ensure that duplicate records are counted only once during reconciliation. There are also withdrawal records that require them to filter out superseded builds. I included a bundle that becomes fully withdrawn, requiring the publisher to omit it from the publishable set. The biggest trap is the keys directory. I left the old revoked key pair in there alongside the current one. If they just grab the first key they find or hardcode the wrong path, the gateway will reject it with an untrusted signature error.

## Grader Design

The verifier dynamically checks the task instead of relying only on hardcoded answers. It verifies that the manifest and expected report remain unchanged, that the provided gateway implementation remains unchanged, that the publisher output matches the golden format, that the actual HTTP publication requests contain the correctly reconciled and canonical descriptors and deterministic request tokens, that the gateway responses are successfully persisted in DuckDB, that the reported key ID matches the gateway's current signing-key response, that rerunning the publisher creates no additional publication requests while producing identical output, that the persisted bundle set matches the SQL reconciliation and that a signature made with the revoked key is rejected by the gateway.

## Verification

The submission handbook requires us to prove the task is both unsolved initially and solvable with the reference code.

### Proof A (Empty Solution)

The empty-environment proof collected seven tests. Four tests failed because the publisher and runtime DuckDB state were absent, while the input-integrity, gateway-integrity and revoked-key tests passed.

Reward output:

```text
0
```

### Proof B (Reference Solution)

The reference solution proof collected seven tests and all seven passed. The publisher reconciled the manifest, signed with the current signing key, published through the gateway, persisted publication state and satisfied the verifier.

Reward output:

```text
1
```
