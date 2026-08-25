import os
import re
import subprocess
import time
import requests
import duckdb
import pytest

GATEWAY_URL = "http://127.0.0.1:7070"
REPORT_EXPECTED = "/app/reports/publications.expected.txt"
DUCKDB_PATH = "/app/releases.duckdb"
REVOKED_CERT = "/app/keys/revoked/revoked.cert.pem"
REVOKED_KEY = "/app/keys/revoked/revoked.key.pem"


@pytest.fixture(scope="session", autouse=True)
def ensure_gateway():
    """Ensure distribution gateway is running before tests execute."""
    gateway_proc = None
    is_running = False

    for _ in range(5):
        try:
            r = requests.get(f"{GATEWAY_URL}/healthz", timeout=1)
            if r.status_code == 200:
                is_running = True
                break
        except requests.exceptions.RequestException:
            time.sleep(0.2)

    if not is_running:
        gateway_proc = subprocess.Popen(
            ["node", "server.js"],
            cwd="/app/distribution-gateway",
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(15):
            try:
                r = requests.get(f"{GATEWAY_URL}/healthz", timeout=1)
                if r.status_code == 200:
                    is_running = True
                    break
            except requests.exceptions.RequestException:
                time.sleep(0.5)

        if not is_running:
            pytest.fail("Gateway failed to become healthy within timeout.")

    yield

    if gateway_proc is not None:
        gateway_proc.terminate()
        gateway_proc.wait(timeout=2)


def get_expected_reconciliation():
    """Dynamically calculates expected bundles from the manifest using SQL."""
    con = duckdb.connect()
    query = """
    WITH manifest AS (
        SELECT DISTINCT * FROM read_csv_auto('/app/fixtures/build_manifest.csv')
    ),
    surviving_builds AS (
        SELECT b.* FROM manifest b
        WHERE b.record_type = 'BUILD'
          AND b.entry_id NOT IN (
              SELECT supersedes_id FROM manifest WHERE record_type = 'WITHDRAWAL'
          )
    )
    SELECT bundle_id, COUNT(*) AS artifact_count, SUM(size_bytes) AS total_bytes
    FROM surviving_builds
    GROUP BY bundle_id
    HAVING COUNT(*) > 0
    ORDER BY bundle_id;
    """
    rows = con.execute(query).fetchall()
    con.close()
    return rows


def mask_receipts(text: str) -> str:
    """Mask dynamic receipt hashes for golden comparison."""
    return re.sub(r"RECEIPT=[^\s]+", "RECEIPT=<id>", text.strip())


def test_publisher_output_matches_golden():
    """Test 1: Run publisher report and match against publications.expected.txt."""
    assert os.path.exists(
        "/app/publisher/release-publisher.mjs"
    ), "release-publisher.mjs is missing"

    result = subprocess.run(
        ["node", "/app/publisher/release-publisher.mjs", "--report"],
        capture_output=True,
        text=True,
        cwd="/app",
    )
    assert result.returncode == 0, f"Publisher failed with error:\n{result.stderr}"

    with open(REPORT_EXPECTED, "r", encoding="utf-8") as f:
        expected_raw = f.read()

    assert mask_receipts(result.stdout) == mask_receipts(expected_raw)


def test_duckdb_persistence_and_receipts():
    """Test 2: Ensure publications are persisted correctly with unique tokens and valid IDs."""
    assert os.path.exists(DUCKDB_PATH), "DuckDB releases.duckdb was not created"

    expected_rows = get_expected_reconciliation()

    con = duckdb.connect(DUCKDB_PATH, read_only=True)
    rows = con.execute(
        "SELECT bundle_id, request_token, publication_id, status FROM publications ORDER BY bundle_id"
    ).fetchall()
    con.close()

    assert len(rows) == len(
        expected_rows
    ), f"Expected {len(expected_rows)} publications in DuckDB, found {len(rows)}"

    tokens = [r[1] for r in rows]
    assert len(tokens) == len(set(tokens)), "Duplicate request tokens found in database"

    for r in rows:
        bundle_id, req_token, pub_id, status = r
        assert (
            req_token == f"token-{bundle_id}"
        ), f"Invalid token format for {bundle_id}"
        assert str(pub_id).startswith(
            "pub_"
        ), f"Invalid publication_id format: {pub_id}"
        assert status == "PUBLISHED", f"Expected status PUBLISHED, got {status}"


def test_idempotency_and_deterministic_rerun():
    """Test 3: Re-running publisher produces identical output and no duplicate DB entries."""
    assert os.path.exists(
        "/app/publisher/release-publisher.mjs"
    ), "release-publisher.mjs is missing"

    run1 = subprocess.run(
        ["node", "/app/publisher/release-publisher.mjs", "--report"],
        capture_output=True,
        text=True,
        cwd="/app",
    )
    run2 = subprocess.run(
        ["node", "/app/publisher/release-publisher.mjs", "--report"],
        capture_output=True,
        text=True,
        cwd="/app",
    )

    assert run1.returncode == 0
    assert run2.returncode == 0
    assert run1.stdout.strip() == run2.stdout.strip()

    expected_rows = get_expected_reconciliation()
    con = duckdb.connect(DUCKDB_PATH, read_only=True)
    count = con.execute("SELECT COUNT(*) FROM publications").fetchone()[0]
    con.close()

    assert count == len(
        expected_rows
    ), f"Expected exactly {len(expected_rows)} publications in DuckDB after rerun, but got {count}."


def test_reconciliation_omits_withdrawn_bundles():
    """Test 4: Verify publisher's DB state matches dynamically computed reconciliation."""
    expected_rows = get_expected_reconciliation()
    expected_bundles = [r[0] for r in expected_rows]

    con_pub = duckdb.connect(DUCKDB_PATH, read_only=True)
    actual_rows = con_pub.execute(
        "SELECT bundle_id FROM publications ORDER BY bundle_id"
    ).fetchall()
    con_pub.close()
    actual_bundles = [r[0] for r in actual_rows]

    assert actual_bundles == expected_bundles, (
        f"Reconciliation failure: Publisher stored {actual_bundles} "
        f"but dynamic calculation expected {expected_bundles}"
    )


def test_gateway_rejects_revoked_key_trap():
    """Test 5: Verify gateway rejects payloads signed with revoked key."""
    desc = '{"artifact_count":1,"bundle_id":"BND-TRAP","total_bytes":100}'
    with open("/tmp/trap_desc.bin", "w", encoding="utf-8") as f:
        f.write(desc)

    subprocess.run(
        [
            "openssl",
            "cms",
            "-sign",
            "-in",
            "/tmp/trap_desc.bin",
            "-signer",
            REVOKED_CERT,
            "-inkey",
            REVOKED_KEY,
            "-outform",
            "PEM",
            "-binary",
            "-out",
            "/tmp/trap_sig.pem",
        ],
        check=True,
    )

    with open("/tmp/trap_sig.pem", "r", encoding="utf-8") as f:
        sig = f.read()

    res = requests.post(
        f"{GATEWAY_URL}/v1/publications",
        json={"descriptor": desc, "signature": sig, "request_token": "token-trap-1"},
        timeout=5,
    )

    assert res.status_code == 400
    assert res.json().get("error") == "UNTRUSTED_SIGNATURE"
