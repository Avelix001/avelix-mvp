-- AVELIX Build 2 complete schema for a fresh database.
CREATE TABLE IF NOT EXISTS profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  avx_id TEXT NOT NULL UNIQUE,
  account_type TEXT NOT NULL DEFAULT 'individual',
  card_tier TEXT NOT NULL DEFAULT 'basic',
  full_name TEXT NOT NULL,
  title TEXT,
  organization TEXT,
  industry TEXT,
  location TEXT,
  email TEXT,
  phone TEXT,
  website TEXT,
  bio TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  cac_number TEXT,
  referral_code TEXT UNIQUE,
  referred_by_profile_id INTEGER,
  referral_count INTEGER NOT NULL DEFAULT 0,
  avx_balance INTEGER NOT NULL DEFAULT 0,
  skills TEXT,
  qualifications TEXT,
  certifications TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  profile_id INTEGER NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  email_verified INTEGER NOT NULL DEFAULT 0,
  verification_code_hash TEXT,
  verification_expires_at INTEGER,
  verification_attempts INTEGER NOT NULL DEFAULT 0,
  last_verification_sent_at INTEGER,
  twofa_enabled INTEGER NOT NULL DEFAULT 0,
  totp_secret TEXT,
  totp_secret_pending TEXT,
  recovery_codes_json TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS share_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  profile_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  fields_json TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  max_uses INTEGER NOT NULL DEFAULT 1,
  use_count INTEGER NOT NULL DEFAULT 0,
  revoked_at INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at INTEGER,
  FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_share_tokens_token_hash ON share_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_share_tokens_profile_id ON share_tokens(profile_id);
CREATE INDEX IF NOT EXISTS idx_profiles_account_type ON profiles(account_type);
CREATE INDEX IF NOT EXISTS idx_profiles_card_tier ON profiles(card_tier);
CREATE INDEX IF NOT EXISTS idx_profiles_referred_by ON profiles(referred_by_profile_id);

CREATE TABLE IF NOT EXISTS auth_challenges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_auth_challenges_token_hash ON auth_challenges(token_hash);
CREATE INDEX IF NOT EXISTS idx_auth_challenges_expires_at ON auth_challenges(expires_at);

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
  FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_credentials_profile_id ON credentials(profile_id);
CREATE INDEX IF NOT EXISTS idx_credentials_status ON credentials(status);
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_user_id INTEGER,
  action TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  details TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_target ON audit_logs(target_type,target_id);

CREATE TABLE IF NOT EXISTS platform_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT '0',
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS avx_packages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  price_ngn INTEGER NOT NULL,
  avx_amount INTEGER NOT NULL,
  description TEXT,
  active INTEGER NOT NULL DEFAULT 0,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS avx_transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  profile_id INTEGER NOT NULL,
  type TEXT NOT NULL,
  amount INTEGER NOT NULL,
  reference TEXT,
  note TEXT,
  created_by_admin_email TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_avx_transactions_profile_id ON avx_transactions(profile_id);
CREATE TABLE IF NOT EXISTS jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  employer TEXT NOT NULL,
  location TEXT,
  work_mode TEXT,
  employment_type TEXT,
  required_skills TEXT,
  required_qualifications TEXT,
  required_certificates TEXT,
  min_experience INTEGER NOT NULL DEFAULT 0,
  apply_url TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_jobs_active ON jobs(active);

INSERT OR IGNORE INTO platform_settings(key,value) VALUES
 ('avx_enabled','0'),('global_search_enabled','0'),('verified_credentials_enabled','0'),('verify_mark_enabled','0'),('cards_enabled','0'),('job_search_enabled','1');

INSERT INTO jobs(title,employer,location,work_mode,employment_type,required_skills,required_qualifications,required_certificates,min_experience,apply_url,active) VALUES
 ('Software Developer','AVELIX Demo Employer','Remote','Remote','Full-time','JavaScript, Python, SQL, Git','B.Sc. Computer Science or related qualification','AWS or equivalent cloud certificate',1,'',1),
 ('Mechanical Technician','AVELIX Demo Employer','Kaduna, Nigeria','Onsite','Full-time','Mechanical maintenance, CAD, troubleshooting','HND Mechanical Engineering or technical qualification','Trade certificate or relevant technical certificate',2,'',1),
 ('Project Manager','AVELIX Demo Employer','Hybrid','Hybrid','Full-time','Project management, communication, planning, Agile','B.Sc. or equivalent professional qualification','PMP or equivalent project certificate',3,'',1),
 ('Marketing Specialist','AVELIX Demo Employer','Remote','Remote','Full-time','Digital marketing, social media, analytics, content','Marketing, Business, Communications or related qualification','Google Ads, Meta or equivalent certificate',1,'',1);

-- AVX treasury: 1 billion AVX reserved at launch, initially locked.
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
