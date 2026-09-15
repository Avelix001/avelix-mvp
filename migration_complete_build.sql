-- AVELYX Complete Build migration for the EXISTING D1 database.
-- Do NOT rerun schema.sql. Run each statement once if the corresponding object
-- is not already present. The Worker also creates the critical tables defensively.

CREATE TABLE IF NOT EXISTS institutions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  state TEXT,
  country TEXT NOT NULL DEFAULT 'Nigeria',
  institution_type TEXT,
  status TEXT NOT NULL DEFAULT 'onboarding',
  verification_method TEXT DEFAULT 'manual',
  processing_time TEXT DEFAULT 'Up to 3 working days',
  contact_name TEXT,
  contact_email TEXT,
  contact_phone TEXT,
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_institutions_status ON institutions(status,name);

CREATE TABLE IF NOT EXISTS institution_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  profile_id INTEGER NOT NULL,
  institution_name TEXT NOT NULL,
  state TEXT,
  reason TEXT,
  status TEXT NOT NULL DEFAULT 'requested',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_institution_requests_status ON institution_requests(status,created_at);

CREATE TABLE IF NOT EXISTS verification_submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  profile_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  institution_id INTEGER NOT NULL,
  credential_type TEXT NOT NULL,
  qualification TEXT NOT NULL,
  programme TEXT,
  graduation_year TEXT,
  reference TEXT,
  file_name TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  data_base64 TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'submitted',
  avx_cost INTEGER NOT NULL DEFAULT 10,
  notes TEXT,
  institution_response TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(institution_id) REFERENCES institutions(id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_verification_submissions_profile ON verification_submissions(profile_id,created_at);
CREATE INDEX IF NOT EXISTS idx_verification_submissions_status ON verification_submissions(status,created_at);

CREATE TABLE IF NOT EXISTS profile_photos (
  profile_id INTEGER PRIMARY KEY,
  mime_type TEXT NOT NULL,
  data_base64 TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS profile_locks (
  profile_id INTEGER PRIMARY KEY,
  locked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS platform_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT '0',
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO platform_settings(key,value) VALUES ('verification_cost_avx','10');
