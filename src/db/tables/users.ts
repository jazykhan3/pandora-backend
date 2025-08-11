import db from '../index';

export function createUsersTable() {
  db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      org_name TEXT,
      industry TEXT,
      role TEXT,
      two_factor_enabled INTEGER DEFAULT 0,
      account_active INTEGER DEFAULT 1,
      created_at INTEGER DEFAULT (strftime('%s','now'))
    )
  `).run();
}