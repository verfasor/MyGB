-- Guestbook Database Schema
-- Run this with: wrangler d1 execute guestbook-db --file=schema.sql

CREATE TABLE IF NOT EXISTS entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  message TEXT NOT NULL,
  site TEXT,
  email TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  approved INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_approved ON entries(approved);
CREATE INDEX IF NOT EXISTS idx_created_at ON entries(created_at);

-- Settings table for dynamic configuration
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);
