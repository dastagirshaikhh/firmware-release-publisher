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

The submission handbook requires us to prove the task is both unsolved initially and solvable with the reference code. Both proofs below were run in a freshly built container (`docker build -t task-img .` from `environment/`), with raw terminal output pasted verbatim.

### Proof A (Empty Solution) — expect reward 0

Command:

```
docker run --rm -it `
  -v "${PWD}\tests:/tests:ro" `
  task-img `
  bash -lc "bash /tests/test.sh; cat /logs/verifier/reward.txt"
```

Output:

```text
=============================================================== test session starts ================================================================
platform linux -- Python 3.11.2, pytest-8.4.1, pluggy-1.6.0
cachedir: /tmp/.pytest_cache
rootdir: /tests
plugins: json-ctrf-0.3.5
collected 7 items

../tests/test_outputs.py ..FFFF.                                                                                                             [100%]

===================================================================== FAILURES =====================================================================
_______________________________________________________ test_publisher_output_matches_golden _______________________________________________________
AssertionError: release-publisher.mjs is missing
_______________________________________________________ test_duckdb_persistence_and_receipts _______________________________________________________
AssertionError: DuckDB releases.duckdb was not created
_____________________________________________________ test_idempotency_and_deterministic_rerun _____________________________________________________
AssertionError: release-publisher.mjs is missing
___________________________________________________ test_reconciliation_omits_withdrawn_bundles ____________________________________________________
AssertionError: DuckDB releases.duckdb was not created

============================================================= short test summary info ==============================================================
PASSED ../tests/test_outputs.py::test_input_files_are_unmodified
PASSED ../tests/test_outputs.py::test_gateway_files_are_unmodified
PASSED ../tests/test_outputs.py::test_gateway_rejects_revoked_key_trap
FAILED ../tests/test_outputs.py::test_publisher_output_matches_golden - AssertionError: release-publisher.mjs is missing
FAILED ../tests/test_outputs.py::test_duckdb_persistence_and_receipts - AssertionError: DuckDB releases.duckdb was not created
FAILED ../tests/test_outputs.py::test_idempotency_and_deterministic_rerun - AssertionError: release-publisher.mjs is missing
FAILED ../tests/test_outputs.py::test_reconciliation_omits_withdrawn_bundles - AssertionError: DuckDB releases.duckdb was not created
=========================================================== 4 failed, 3 passed in 2.18s ============================================================
pytest exit code: 1
0
```

With no solution installed, the four tests that depend on the publisher's own output all fail as expected (`/app/publisher/release-publisher.mjs` and `/app/releases.duckdb` don't exist yet), while the three tests that only check the provided environment (fixture integrity, gateway integrity, revoked-key rejection) pass on their own. Overall pytest exit code is 1, so `reward.txt` is `0`. This proves the task is genuinely unsolved out of the box.

### Proof B (Reference Solution) — expect reward 1

Command:

```
docker run --rm -it `
  -v "${PWD}\tests:/tests:ro" `
  -v "${PWD}\solution:/solution:ro" `
  task-img `
  bash -lc "bash /solution/publish.sh && bash /tests/test.sh; cat /logs/verifier/reward.txt"
```

Output:

```text
BUNDLE BND-101 SIGNED KEY=fw-signing-2026-current
BUNDLE BND-101 PUBLISHED RECEIPT=pub_2ddbc99a7d61de760ba53efa TOKEN=token-BND-101 STATUS=PUBLISHED
BUNDLE BND-102 SIGNED KEY=fw-signing-2026-current
BUNDLE BND-102 PUBLISHED RECEIPT=pub_b5b7505be5fdb0a83e0cf2fe TOKEN=token-BND-102 STATUS=PUBLISHED
BUNDLE BND-103 SIGNED KEY=fw-signing-2026-current
BUNDLE BND-103 PUBLISHED RECEIPT=pub_404c37f532f423478ce20ce7 TOKEN=token-BND-103 STATUS=PUBLISHED
=============================================================== test session starts ================================================================
platform linux -- Python 3.11.2, pytest-8.4.1, pluggy-1.6.0
cachedir: /tmp/.pytest_cache
rootdir: /tests
plugins: json-ctrf-0.3.5
collected 7 items

../tests/test_outputs.py .......                                                                                                             [100%]

============================================================= short test summary info ==============================================================
PASSED ../tests/test_outputs.py::test_input_files_are_unmodified
PASSED ../tests/test_outputs.py::test_gateway_files_are_unmodified
PASSED ../tests/test_outputs.py::test_publisher_output_matches_golden
PASSED ../tests/test_outputs.py::test_duckdb_persistence_and_receipts
PASSED ../tests/test_outputs.py::test_idempotency_and_deterministic_rerun
PASSED ../tests/test_outputs.py::test_reconciliation_omits_withdrawn_bundles
PASSED ../tests/test_outputs.py::test_gateway_rejects_revoked_key_trap
================================================================ 7 passed in 2.74s =================================================================
pytest exit code: 0
1
```

`solution/publish.sh` installed `release-publisher.mjs` into `/app/publisher/`, started the gateway and ran the publisher, which reconciled the manifest, signed each publishable bundle (`BND-101`, `BND-102`, `BND-103`) with the current key, published them and persisted the receipts to DuckDB. All seven tests pass and `reward.txt` is `1`. This proves the task is solvable and the grader is correct.
