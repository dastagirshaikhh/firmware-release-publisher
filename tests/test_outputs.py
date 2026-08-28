import hashlib
import json
import os
import re
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import duckdb
import pytest
import requests


GATEWAY_URL = "http://127.0.0.1:7070"
PROXY_URL = "http://127.0.0.1:7071"

REPORT_EXPECTED = "/app/reports/publications.expected.txt"
DUCKDB_PATH = "/app/releases.duckdb"
MANIFEST_PATH = "/app/fixtures/build_manifest.csv"
GATEWAY_SOURCE_ROOT = "/app/distribution-gateway"

REVOKED_CERT = "/app/keys/revoked/revoked.cert.pem"
REVOKED_KEY = "/app/keys/revoked/revoked.key.pem"

EXPECTED_MANIFEST_SHA256 = (
    "599bd7c0aa4cbffe0df76ef3757f9a48bb62d9335513719990f63f02392fdfce"
)
EXPECTED_GOLDEN_SHA256 = (
    "159b21e33858a64de7a60f04601677e74b7b9f38fcb80b04113ea1b4243e405e"
)
EXPECTED_GATEWAY_SHA256 = (
    "9273f4f1241c56775fc347a6422d910a41abb91e95792c9a92e94d55b4fa5011"
)


@pytest.fixture(scope="session", autouse=True)
def ensure_gateway():
    """Ensure the distribution gateway is running before tests execute."""
    gateway_proc = None
    is_running = False

    for _ in range(5):
        try:
            response = requests.get(
                f"{GATEWAY_URL}/healthz",
                timeout=1,
            )
            if response.status_code == 200:
                is_running = True
                break
        except requests.exceptions.RequestException:
            time.sleep(0.2)

    if not is_running:
        gateway_proc = subprocess.Popen(
            ["node", "server.js"],
            cwd=GATEWAY_SOURCE_ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        for _ in range(15):
            try:
                response = requests.get(
                    f"{GATEWAY_URL}/healthz",
                    timeout=1,
                )
                if response.status_code == 200:
                    is_running = True
                    break
            except requests.exceptions.RequestException:
                time.sleep(0.5)

        if not is_running:
            pytest.fail("Gateway failed to become healthy.")

    yield

    if gateway_proc is not None:
        gateway_proc.terminate()
        try:
            gateway_proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            gateway_proc.kill()
            gateway_proc.wait(timeout=2)


class CaptureProxyHandler(BaseHTTPRequestHandler):
    """Capture publisher HTTP traffic while forwarding it to the gateway."""

    server_version = "HurixVerifierProxy/1.0"

    def log_message(self, format, *args):
        return

    def _forward(self, method):
        parsed = urlparse(self.path)
        target_url = f"{GATEWAY_URL}{parsed.path}"

        if parsed.query:
            target_url += f"?{parsed.query}"

        body = b""

        if method in {"POST", "PUT", "PATCH"}:
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                content_length = 0

            body = self.rfile.read(content_length)

        forwarded_headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in {"host", "content-length"}
        }

        try:
            response = requests.request(
                method=method,
                url=target_url,
                headers=forwarded_headers,
                data=body if body else None,
                timeout=10,
            )
        except requests.RequestException as exc:
            self.send_response(502)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(str(exc).encode("utf-8"))
            return

        if method == "GET" and parsed.path == "/v1/signing-key/current":
            try:
                key_data = response.json()
            except ValueError:
                key_data = None

            self.server.captured_signing_key = key_data

        if method == "POST" and parsed.path == "/v1/publications":
            try:
                parsed_body = json.loads(body.decode("utf-8"))
            except (
                UnicodeDecodeError,
                json.JSONDecodeError,
            ):
                parsed_body = None

            try:
                response_json = response.json()
            except ValueError:
                response_json = None

            self.server.publication_requests.append(
                {
                    "body": parsed_body,
                    "raw_body": body,
                    "status_code": response.status_code,
                    "response_text": response.text,
                    "response_json": response_json,
                }
            )

        self.send_response(response.status_code)

        for key, value in response.headers.items():
            if key.lower() in {
                "content-length",
                "transfer-encoding",
                "content-encoding",
                "connection",
            }:
                continue

            self.send_header(key, value)

        self.send_header(
            "Content-Length",
            str(len(response.content)),
        )
        self.end_headers()

        self.wfile.write(response.content)

    def do_GET(self):
        self._forward("GET")

    def do_POST(self):
        self._forward("POST")


@pytest.fixture(scope="session")
def capture_proxy(ensure_gateway):
    """Start the HTTP capture proxy."""
    server = ThreadingHTTPServer(
        ("127.0.0.1", 7071),
        CaptureProxyHandler,
    )

    server.publication_requests = []
    server.captured_signing_key = None

    thread = threading.Thread(
        target=server.serve_forever,
        name="hurix-capture-proxy",
        daemon=True,
    )
    thread.start()

    for _ in range(20):
        try:
            response = requests.get(
                f"{PROXY_URL}/healthz",
                timeout=1,
            )
            if response.status_code == 200:
                break
        except requests.RequestException:
            time.sleep(0.1)
    else:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        pytest.fail("Capture proxy failed to become healthy.")

    yield server

    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def publisher_env():
    """Environment used to route publisher HTTP traffic through the proxy."""
    return {
        **os.environ,
        "GATEWAY_URL": PROXY_URL,
    }


def sha256_file(path):
    """Return the SHA-256 digest of a file."""
    digest = hashlib.sha256()

    with open(path, "rb") as handle:
        for chunk in iter(
            lambda: handle.read(65536),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def sha256_tree(root):
    digest = hashlib.sha256()
    root_path = os.path.abspath(root)
    files = []

    for current_root, dirs, filenames in os.walk(root_path):
        dirs[:] = sorted(d for d in dirs if d not in {"data", "node_modules", ".git"})

        for filename in filenames:
            if filename == "package-lock.json":
                continue

            full_path = os.path.join(
                current_root,
                filename,
            )

            relative_path = os.path.relpath(
                full_path,
                root_path,
            ).replace(os.sep, "/")

            files.append((relative_path, full_path))

    for relative_path, full_path in sorted(files):
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")

        with open(full_path, "rb") as handle:
            for chunk in iter(
                lambda: handle.read(65536),
                b"",
            ):
                digest.update(chunk)

    return digest.hexdigest()


def test_input_files_are_unmodified():
    """Verify immutable grader inputs were not modified."""
    assert os.path.exists(MANIFEST_PATH), "Build manifest is missing"

    assert os.path.exists(REPORT_EXPECTED), "Expected report is missing"

    assert (
        sha256_file(MANIFEST_PATH) == EXPECTED_MANIFEST_SHA256
    ), "Build manifest was modified"

    assert (
        sha256_file(REPORT_EXPECTED) == EXPECTED_GOLDEN_SHA256
    ), "Expected report was modified"


def test_gateway_files_are_unmodified():
    """Verify the provided gateway source has not been changed."""
    assert os.path.isdir(
        GATEWAY_SOURCE_ROOT
    ), "Distribution gateway directory is missing"

    assert (
        sha256_tree(GATEWAY_SOURCE_ROOT) == EXPECTED_GATEWAY_SHA256
    ), "Provided distribution gateway files were modified"


def get_expected_reconciliation():
    """Dynamically calculate expected publishable bundles using SQL."""
    con = duckdb.connect()

    query = """
    WITH manifest AS (
        SELECT DISTINCT *
        FROM read_csv_auto(
            '/app/fixtures/build_manifest.csv'
        )
    ),
    surviving_builds AS (
        SELECT b.*
        FROM manifest b
        WHERE b.record_type = 'BUILD'
          AND b.entry_id NOT IN (
              SELECT supersedes_id
              FROM manifest
              WHERE record_type = 'WITHDRAWAL'
          )
    )
    SELECT
        bundle_id,
        COUNT(*) AS artifact_count,
        SUM(size_bytes) AS total_bytes
    FROM surviving_builds
    GROUP BY bundle_id
    HAVING COUNT(*) > 0
    ORDER BY bundle_id;
    """

    try:
        rows = con.execute(query).fetchall()
    finally:
        con.close()

    return rows


def mask_receipts(text):
    """Mask dynamic receipt IDs for golden comparison."""
    return re.sub(
        r"RECEIPT=[^\s]+",
        "RECEIPT=<id>",
        text.strip(),
    )


def canonical_descriptor(descriptor):
    """Serialize a descriptor using the required canonical JSON format."""
    return json.dumps(
        descriptor,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def assert_captured_publications_match_expected(
    proxy,
    expected_rows,
):
    """Validate the actual publication requests observed by the proxy."""
    requests_seen = list(proxy.publication_requests)

    assert len(requests_seen) == len(expected_rows), (
        f"Expected {len(expected_rows)} publication POSTs, "
        f"captured {len(requests_seen)}"
    )

    expected_by_bundle = {
        bundle_id: (
            artifact_count,
            total_bytes,
        )
        for bundle_id, artifact_count, total_bytes in expected_rows
    }

    captured_bundles = []

    for record in requests_seen:
        assert record["status_code"] == 200, (
            f"Gateway publication returned HTTP "
            f"{record['status_code']}: "
            f"{record['response_text']}"
        )

        payload = record["body"]

        assert isinstance(
            payload,
            dict,
        ), "Publication body is not valid JSON"

        assert set(payload) == {
            "descriptor",
            "signature",
            "request_token",
        }, "Unexpected publication request fields"

        descriptor_text = payload["descriptor"]

        assert isinstance(
            descriptor_text,
            str,
        ), "Descriptor must be a JSON string"

        try:
            descriptor = json.loads(descriptor_text)
        except json.JSONDecodeError as exc:
            pytest.fail(f"Descriptor is not valid JSON: {exc}")

        assert isinstance(
            descriptor,
            dict,
        ), "Descriptor JSON must be an object"

        assert set(descriptor.keys()) == {
            "artifact_count",
            "bundle_id",
            "total_bytes",
        }, (
            f"Unexpected descriptor fields: " f"{descriptor.keys()}"
        )

        bundle_id = descriptor["bundle_id"]

        assert (
            bundle_id in expected_by_bundle
        ), f"Unexpected bundle submitted: {bundle_id}"

        expected_count, expected_bytes = expected_by_bundle[bundle_id]

        assert descriptor["artifact_count"] == expected_count, (
            f"{bundle_id}: expected artifact_count "
            f"{expected_count}, got "
            f"{descriptor['artifact_count']}"
        )

        assert descriptor["total_bytes"] == expected_bytes, (
            f"{bundle_id}: expected total_bytes "
            f"{expected_bytes}, got "
            f"{descriptor['total_bytes']}"
        )

        assert payload["request_token"] == (f"token-{bundle_id}"), (
            f"{bundle_id}: invalid request token " f"{payload['request_token']}"
        )

        assert descriptor_text == (
            canonical_descriptor(descriptor)
        ), f"{bundle_id}: descriptor is not canonical JSON"

        assert payload["signature"], f"{bundle_id}: missing CMS signature"

        gateway_response = record.get("response_json")

        assert isinstance(
            gateway_response,
            dict,
        ), (
            f"{bundle_id}: gateway response " f"is not valid JSON"
        )

        assert gateway_response.get("status") == "PUBLISHED", (
            f"{bundle_id}: gateway returned "
            f"unexpected status "
            f"{gateway_response.get('status')}"
        )

        assert gateway_response.get("request_token") == payload["request_token"], (
            f"{bundle_id}: gateway request token "
            f"{gateway_response.get('request_token')} "
            f"does not match submitted token "
            f"{payload['request_token']}"
        )

        gateway_publication_id = gateway_response.get("publication_id")

        assert gateway_publication_id, (
            f"{bundle_id}: gateway did not return " f"publication_id"
        )

        assert str(gateway_publication_id).startswith("pub_"), (
            f"{bundle_id}: invalid gateway "
            f"publication_id "
            f"{gateway_publication_id}"
        )

        captured_bundles.append(bundle_id)

    assert len(captured_bundles) == len(set(captured_bundles)), (
        "Duplicate bundle publications captured: " f"{captured_bundles}"
    )

    assert captured_bundles == sorted(captured_bundles), (
        "Publication POSTs were not ordered by " f"bundle_id: {captured_bundles}"
    )

    assert captured_bundles == sorted(expected_by_bundle), (
        f"Submitted bundles {captured_bundles} "
        f"do not match expected bundles "
        f"{sorted(expected_by_bundle)}"
    )


def test_publisher_output_matches_golden(
    capture_proxy,
):
    """Validate output, HTTP requests, receipts, and key ID."""
    assert os.path.exists(
        "/app/publisher/release-publisher.mjs"
    ), "release-publisher.mjs is missing"

    if os.path.exists(DUCKDB_PATH):
        os.remove(DUCKDB_PATH)

    capture_proxy.publication_requests.clear()
    capture_proxy.captured_signing_key = None

    result = subprocess.run(
        [
            "node",
            "/app/publisher/release-publisher.mjs",
            "--report",
        ],
        capture_output=True,
        text=True,
        cwd="/app",
        env=publisher_env(),
    )

    assert result.returncode == 0, f"Publisher failed with error:\n" f"{result.stderr}"

    with open(
        REPORT_EXPECTED,
        "r",
        encoding="utf-8",
    ) as handle:
        expected_raw = handle.read()

    assert mask_receipts(result.stdout) == mask_receipts(expected_raw)

    assert capture_proxy.captured_signing_key is not None, (
        "Publisher did not query " "/v1/signing-key/current"
    )

    gateway_key_id = capture_proxy.captured_signing_key.get("key_id")

    assert gateway_key_id, "Gateway current-key response " "did not contain key_id"

    expected_rows = get_expected_reconciliation()

    assert_captured_publications_match_expected(
        capture_proxy,
        expected_rows,
    )

    assert os.path.exists(DUCKDB_PATH), "DuckDB releases.duckdb was not created"

    con = duckdb.connect(
        DUCKDB_PATH,
        read_only=True,
    )

    try:
        db_rows = con.execute(
            """
            SELECT
                bundle_id,
                request_token,
                publication_id,
                status
            FROM publications
            ORDER BY bundle_id
            """
        ).fetchall()
    finally:
        con.close()

    assert len(db_rows) == len(expected_rows), (
        f"Expected {len(expected_rows)} DuckDB " f"rows, found {len(db_rows)}"
    )

    db_by_token = {
        request_token: (
            bundle_id,
            publication_id,
            status,
        )
        for (
            bundle_id,
            request_token,
            publication_id,
            status,
        ) in db_rows
    }

    for record in capture_proxy.publication_requests:
        payload = record["body"]
        gateway_response = record["response_json"]

        token = payload["request_token"]

        assert token in db_by_token, (
            f"Gateway publication token {token} " f"is missing from DuckDB"
        )

        (
            bundle_id,
            db_publication_id,
            db_status,
        ) = db_by_token[token]

        gateway_publication_id = gateway_response["publication_id"]
        gateway_request_token = gateway_response["request_token"]
        gateway_status = gateway_response["status"]

        assert gateway_request_token == token, (
            f"{bundle_id}: gateway returned "
            f"request token {gateway_request_token}, "
            f"expected {token}"
        )

        assert gateway_status == "PUBLISHED", (
            f"{bundle_id}: gateway returned status " f"{gateway_status}"
        )

        assert db_publication_id == (gateway_publication_id), (
            f"{bundle_id}: DuckDB publication_id "
            f"{db_publication_id} does not match "
            f"gateway publication_id "
            f"{gateway_publication_id}"
        )

        assert db_status == "PUBLISHED", (
            f"{bundle_id}: DuckDB status " f"{db_status} is not PUBLISHED"
        )

    signed_lines = [
        line for line in result.stdout.splitlines() if " SIGNED KEY=" in line
    ]

    assert signed_lines, "Publisher produced no SIGNED output lines"

    for line in signed_lines:
        reported_key_id = line.split(
            "KEY=",
            1,
        )[1]

        assert reported_key_id == (gateway_key_id), (
            f"Publisher reported key_id "
            f"{reported_key_id}, but gateway "
            f"returned {gateway_key_id}"
        )


def test_duckdb_persistence_and_receipts():
    """Validate persisted publication state."""
    assert os.path.exists(DUCKDB_PATH), "DuckDB releases.duckdb was not created"

    expected_rows = get_expected_reconciliation()

    con = duckdb.connect(
        DUCKDB_PATH,
        read_only=True,
    )

    try:
        rows = con.execute(
            """
            SELECT
                bundle_id,
                request_token,
                publication_id,
                status
            FROM publications
            ORDER BY bundle_id
            """
        ).fetchall()
    finally:
        con.close()

    assert len(rows) == len(expected_rows), (
        f"Expected {len(expected_rows)} "
        f"publications in DuckDB, "
        f"found {len(rows)}"
    )

    tokens = [row[1] for row in rows]

    assert len(tokens) == len(set(tokens)), "Duplicate request tokens found in database"

    for (
        bundle_id,
        request_token,
        publication_id,
        status,
    ) in rows:
        assert request_token == (f"token-{bundle_id}"), (
            f"Invalid token format for " f"{bundle_id}"
        )

        assert str(publication_id).startswith("pub_"), (
            f"Invalid publication_id format: " f"{publication_id}"
        )

        assert status == "PUBLISHED", f"Expected status PUBLISHED, " f"got {status}"


def test_idempotency_and_deterministic_rerun(
    capture_proxy,
):
    """Verify deterministic reruns create no new publications."""
    assert os.path.exists(
        "/app/publisher/release-publisher.mjs"
    ), "release-publisher.mjs is missing"

    expected_rows = get_expected_reconciliation()

    if os.path.exists(DUCKDB_PATH):
        os.remove(DUCKDB_PATH)

    capture_proxy.publication_requests.clear()
    capture_proxy.captured_signing_key = None

    run1 = subprocess.run(
        [
            "node",
            "/app/publisher/release-publisher.mjs",
            "--report",
        ],
        capture_output=True,
        text=True,
        cwd="/app",
        env=publisher_env(),
    )

    assert run1.returncode == 0, f"First publisher run failed:\n" f"{run1.stderr}"

    posts_after_first = len(capture_proxy.publication_requests)

    assert posts_after_first == len(expected_rows), (
        f"Expected {len(expected_rows)} "
        f"publication POSTs on first run, "
        f"captured {posts_after_first}"
    )

    run2 = subprocess.run(
        [
            "node",
            "/app/publisher/release-publisher.mjs",
            "--report",
        ],
        capture_output=True,
        text=True,
        cwd="/app",
        env=publisher_env(),
    )

    assert run2.returncode == 0, f"Second publisher run failed:\n" f"{run2.stderr}"

    posts_after_second = len(capture_proxy.publication_requests)

    assert run1.stdout == run2.stdout, (
        "Repeated publisher runs produced " "different output"
    )

    assert posts_after_second == (posts_after_first), (
        "Second publisher run created " "additional gateway publication " "requests"
    )

    assert os.path.exists(DUCKDB_PATH), "DuckDB releases.duckdb missing " "after rerun"

    con = duckdb.connect(
        DUCKDB_PATH,
        read_only=True,
    )

    try:
        count = con.execute("SELECT COUNT(*) FROM publications").fetchone()[0]
    finally:
        con.close()

    assert count == len(expected_rows), (
        f"Expected exactly {len(expected_rows)} "
        f"publications after rerun, "
        f"but got {count}"
    )


def test_reconciliation_omits_withdrawn_bundles():
    """Verify persisted bundles match SQL reconciliation."""
    expected_rows = get_expected_reconciliation()
    expected_bundles = [row[0] for row in expected_rows]

    assert os.path.exists(DUCKDB_PATH), "DuckDB releases.duckdb was not created"

    con = duckdb.connect(
        DUCKDB_PATH,
        read_only=True,
    )

    try:
        actual_rows = con.execute(
            """
            SELECT bundle_id
            FROM publications
            ORDER BY bundle_id
            """
        ).fetchall()
    finally:
        con.close()

    actual_bundles = [row[0] for row in actual_rows]

    assert actual_bundles == expected_bundles, (
        f"Reconciliation failure: Publisher "
        f"stored {actual_bundles} but dynamic "
        f"calculation expected {expected_bundles}"
    )


def test_gateway_rejects_revoked_key_trap():
    """Verify gateway rejects payloads signed with revoked key."""
    descriptor = '{"artifact_count":1,' '"bundle_id":"BND-TRAP",' '"total_bytes":100}'

    descriptor_path = "/tmp/trap_desc.bin"
    signature_path = "/tmp/trap_sig.pem"

    with open(
        descriptor_path,
        "w",
        encoding="utf-8",
    ) as handle:
        handle.write(descriptor)

    subprocess.run(
        [
            "openssl",
            "cms",
            "-sign",
            "-in",
            descriptor_path,
            "-signer",
            REVOKED_CERT,
            "-inkey",
            REVOKED_KEY,
            "-outform",
            "PEM",
            "-binary",
            "-out",
            signature_path,
        ],
        check=True,
    )

    with open(
        signature_path,
        "r",
        encoding="utf-8",
    ) as handle:
        signature = handle.read()

    response = requests.post(
        f"{GATEWAY_URL}/v1/publications",
        json={
            "descriptor": descriptor,
            "signature": signature,
            "request_token": "token-trap-1",
        },
        timeout=5,
    )

    assert response.status_code == 400
    assert response.json().get("error") == "UNTRUSTED_SIGNATURE"
