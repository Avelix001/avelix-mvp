-- AVELIX AVX Treasury migration.
-- Run this once after migration_launch.sql on the existing D1 database.
-- Creates a fixed 1,000,000,000 AVX reserve and keeps all supply LOCKED.
CREATE TABLE IF NOT EXISTS avx_treasury (
  id INTEGER PRIMARY KEY CHECK (id=1),
  max_supply INTEGER NOT NULL,
  unlocked_amount INTEGER NOT NULL DEFAULT 0,
  issued_amount INTEGER NOT NULL DEFAULT 0,
  locked INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO avx_treasury(id,max_supply,unlocked_amount,issued_amount,locked)
VALUES (1,1000000000,0,0,1);
