CREATE TABLE IF NOT EXISTS information_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  requester_user_id INTEGER NOT NULL,
  requester_name TEXT NOT NULL,
  requester_email TEXT,
  profile_id INTEGER NOT NULL,
  request_type TEXT NOT NULL DEFAULT 'profile',
  requested_fields TEXT NOT NULL,
  reason TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  approved_fields TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  responded_at INTEGER,
  expires_at INTEGER,
  FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_information_requests_profile_status
ON information_requests(profile_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_information_requests_requester
ON information_requests(requester_user_id, created_at);
