const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = process.env.VERCEL ? path.join('/tmp', 'database.db') : './database.db';

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error("Error opening database " + err.message);
    } else {
        console.log(`Database connected at ${dbPath}`);
    }
});

const createTableQuery = `
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    api_key TEXT UNIQUE
);`;

db.run(createTableQuery, (err) => {
    if (err) {
        console.error("Error creating table: ", err.message);
    } else {
        console.log("Users table is ready.");
    }
});

module.exports = db;