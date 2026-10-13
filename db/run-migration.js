// One-off runner: applies db/schema.sql statement-by-statement against the
// transaction pooler (port 6543), which doesn't reliably handle a single
// multi-statement query the way a direct session connection would.
const fs = require("fs");
const path = require("path");
const { Client } = require("pg");

const sql = fs.readFileSync(path.join(__dirname, "schema.sql"), "utf8");
// Strip -- line comments before splitting, so a semicolon mentioned inside a
// comment (e.g. "-- references users(id); nullable...") doesn't fracture
// the statement it's commenting on.
const sqlNoComments = sql
    .split("\n")
    .map(line => line.replace(/--.*$/, ""))
    .join("\n");
const statements = sqlNoComments
    .split(";")
    .map(s => s.trim())
    .filter(s => s.length);

const client = new Client({
    host: "aws-0-us-east-1.pooler.supabase.com",
    port: 6543,
    user: "postgres.bfutcalcoegtdtbnpysy",
    password: process.env.DB_PASS,
    database: "postgres",
    ssl: { rejectUnauthorized: false },
});

(async () => {
    await client.connect();
    for (const stmt of statements) {
        try {
            await client.query(stmt);
            console.log("OK:", stmt.slice(0, 60).replace(/\n/g, " "));
        } catch (e) {
            console.log("FAILED:", stmt.slice(0, 60).replace(/\n/g, " "), "--", e.message);
        }
    }
    await client.end();
})();
