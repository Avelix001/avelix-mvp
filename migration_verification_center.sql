-- AVELYX Verification Center
CREATE TABLE IF NOT EXISTS verification_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  profile_id INTEGER NOT NULL,
  verification_type TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  evidence TEXT,
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_verification_requests_profile ON verification_requests(profile_id, created_at);
CREATE INDEX IF NOT EXISTS idx_verification_requests_status ON verification_requests(status, created_at);

-- Credential table required by card eligibility and the admin credential workflow.
CREATE TABLE IF NOT EXISTS credentials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  credential_id TEXT NOT NULL UNIQUE,
  profile_id INTEGER NOT NULL,
  credential_type TEXT NOT NULL,
  title TEXT NOT NULL,
  issuer TEXT,
  reference TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  verified_at INTEGER,
  expires_at INTEGER,
  notes TEXT,
  created_by_admin_email TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_credentials_profile_id ON credentials(profile_id);
CREATE INDEX IF NOT EXISTS idx_credentials_status ON credentials(status);
