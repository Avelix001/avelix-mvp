-- AVELYX Card purchase eligibility and orders
CREATE TABLE IF NOT EXISTS card_orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  profile_id INTEGER NOT NULL,
  card_tier TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending_payment',
  reference TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_card_orders_user_id ON card_orders(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_card_orders_profile_id ON card_orders(profile_id, created_at);
