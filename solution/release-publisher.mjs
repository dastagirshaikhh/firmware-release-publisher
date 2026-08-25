import duckdb from 'duckdb';
import { readFileSync, writeFileSync } from 'fs';
import { execFileSync } from 'child_process';

const DB_PATH = '/app/releases.duckdb';
const MANIFEST_PATH = '/app/fixtures/build_manifest.csv';
const GATEWAY_URL =
    process.env.GATEWAY_URL || 'http://127.0.0.1:7070';

function canonicalize(row) {
    return JSON.stringify({
        artifact_count: Number(row.artifact_count),
        bundle_id: row.bundle_id,
        total_bytes: Number(row.total_bytes)
    });
}

function signDescriptor(descriptor) {
    const descriptorPath = '/tmp/descriptor.bin';
    const signaturePath = '/tmp/signature.pem';

    writeFileSync(descriptorPath, descriptor, 'utf8');

    execFileSync(
        'openssl',
        [
            'cms',
            '-sign',
            '-in', descriptorPath,
            '-signer', '/app/keys/current/current.cert.pem',
            '-inkey', '/app/keys/current/current.key.pem',
            '-outform', 'PEM',
            '-binary',
            '-out', signaturePath
        ],
        { stdio: 'pipe' }
    );

    return readFileSync(signaturePath, 'utf8');
}

function execRun(db, sql, ...args) {
    return new Promise((resolve, reject) => {
        db.run(sql, ...args, err => {
            if (err) reject(err);
            else resolve();
        });
    });
}

function execAll(db, sql, ...args) {
    return new Promise((resolve, reject) => {
        db.all(sql, ...args, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}

async function main() {
    const db = new duckdb.Database(DB_PATH);

    try {
        await execRun(db, `
            CREATE TABLE IF NOT EXISTS publications (
                bundle_id VARCHAR PRIMARY KEY,
                request_token VARCHAR UNIQUE,
                publication_id VARCHAR,
                status VARCHAR
            );
        `);

        const keyResponse = await fetch(
            `${GATEWAY_URL}/v1/signing-key/current`
        );

        if (!keyResponse.ok) {
            throw new Error(
                `Failed to get signing key: ${keyResponse.status}`
            );
        }

        const keyData = await keyResponse.json();

        const query = `
            WITH manifest AS (
                SELECT DISTINCT *
                FROM read_csv_auto('${MANIFEST_PATH}')
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
        `;

        const rows = await execAll(db, query);

        for (const row of rows) {
            const token = `token-${row.bundle_id}`;

            const existing = await execAll(
                db,
                `SELECT publication_id, request_token, status
                 FROM publications
                 WHERE request_token = ?`,
                token
            );

            if (existing.length > 0) {
                console.log(
                    `BUNDLE ${row.bundle_id} SIGNED KEY=${keyData.key_id}`
                );

                console.log(
                    `BUNDLE ${row.bundle_id} PUBLISHED ` +
                    `RECEIPT=${existing[0].publication_id} ` +
                    `TOKEN=${existing[0].request_token} ` +
                    `STATUS=${existing[0].status}`
                );

                continue;
            }

            const descriptor = canonicalize(row);
            const signature = signDescriptor(descriptor);

            console.log(
                `BUNDLE ${row.bundle_id} SIGNED KEY=${keyData.key_id}`
            );

            const response = await fetch(
                `${GATEWAY_URL}/v1/publications`,
                {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        descriptor,
                        signature,
                        request_token: token
                    })
                }
            );

            const data = await response.json();

            if (!response.ok) {
                throw new Error(
                    `${response.status} ${JSON.stringify(data)}`
                );
            }

            await execRun(
                db,
                `INSERT INTO publications
                    (bundle_id, request_token, publication_id, status)
                 VALUES (?, ?, ?, ?)`,
                row.bundle_id,
                data.request_token,
                data.publication_id,
                data.status
            );

            console.log(
                `BUNDLE ${row.bundle_id} PUBLISHED ` +
                `RECEIPT=${data.publication_id} ` +
                `TOKEN=${data.request_token} ` +
                `STATUS=${data.status}`
            );
        }
    } finally {
        db.close();
    }
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});