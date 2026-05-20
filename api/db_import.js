const { Client } = require('pg');
const fs = require('fs');

const inputFile = process.argv[2];
if (!inputFile) {
    console.error("Usage: node import_db.js <input_json>");
    process.exit(1);
}

const client = new Client({
    user: 'haproxy',
    host: 'db',
    database: 'haproxy',
    password: 'haproxy_password_change_me',
    port: 5432,
});

async function run() {
    await client.connect();

    const raw = fs.readFileSync('/app/dns_migration_list.json', 'utf8');
    const domainList = JSON.parse(raw);

    // We assume backend_port 80 and HTTPS redirect True for all
    const sql = `INSERT INTO rules (name, type, domain, backend_host, backend_port, ssl_enabled, ssl_cert, ssl_type, redirect_to_https, active, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW())`;

    let count = 0;

    for (const item of domainList) {
        // Simple name from domain
        const name = item.domain.split('.')[0];

        try {
            await client.query(sql, [
                name,
                'ingress',
                item.domain,
                item.target,
                80,
                true,
                'trtekyazilim.com.pem',
                'wildcard',
                true,
                true
            ]);
            count++;
        } catch (err) {
            console.error(`Failed to insert ${item.domain}:`, err.message);
        }
    }

    console.log(`Inserted ${count} rules into database.`);
    await client.end();
}

run();
