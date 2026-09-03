-- AVELIX COMBINED LAUNCH migration for an EXISTING Build 2 D1 database.
-- Run ONCE. After this migration, platform settings, AVX packages, job listings and wallet credits are controlled from /admin.html.

-- Build 3 security columns.
ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN verification_code_hash TEXT;
ALTER TABLE users ADD COLUMN verification_expires_at INTEGER;
ALTER TABLE users ADD COLUMN verification_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN last_verification_sent_at INTEGER;
ALTER TABLE users ADD COLUMN twofa_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN totp_secret TEXT;
ALTER TABLE users ADD COLUMN totp_secret_pending TEXT;
ALTER TABLE users ADD COLUMN recovery_codes_json TEXT;

CREATE TABLE IF NOT EXISTS auth_challenges (id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,token_hash TEXT NOT NULL UNIQUE,expires_at INTEGER NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS idx_auth_challenges_token_hash ON auth_challenges(token_hash);
CREATE INDEX IF NOT EXISTS idx_auth_challenges_expires_at ON auth_challenges(expires_at);
UPDATE users SET email_verified=1 WHERE email_verified=0;

-- Build 4 credential verification and audit trail.
CREATE TABLE IF NOT EXISTS credentials (id INTEGER PRIMARY KEY AUTOINCREMENT,credential_id TEXT NOT NULL UNIQUE,profile_id INTEGER NOT NULL,credential_type TEXT NOT NULL,title TEXT NOT NULL,issuer TEXT,reference TEXT,status TEXT NOT NULL DEFAULT 'pending',verified_at INTEGER,expires_at INTEGER,notes TEXT,created_by_admin_email TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS idx_credentials_profile_id ON credentials(profile_id);
CREATE INDEX IF NOT EXISTS idx_credentials_status ON credentials(status);
CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT,actor_user_id INTEGER,action TEXT NOT NULL,target_type TEXT,target_id TEXT,details TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL);
CREATE INDEX IF NOT EXISTS idx_audit_logs_target ON audit_logs(target_type,target_id);

-- Job seeker profile evidence.
ALTER TABLE profiles ADD COLUMN skills TEXT;
ALTER TABLE profiles ADD COLUMN qualifications TEXT;
ALTER TABLE profiles ADD COLUMN certifications TEXT;

-- Platform controls.
CREATE TABLE IF NOT EXISTS platform_settings (key TEXT PRIMARY KEY,value TEXT NOT NULL DEFAULT '0',updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
INSERT OR IGNORE INTO platform_settings(key,value) VALUES
 ('avx_enabled','0'),
 ('global_search_enabled','0'),
 ('verified_credentials_enabled','0'),
 ('verify_mark_enabled','0'),
 ('cards_enabled','0'),
 ('job_search_enabled','1');

CREATE TABLE IF NOT EXISTS avx_packages (id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,price_ngn INTEGER NOT NULL,avx_amount INTEGER NOT NULL,description TEXT,active INTEGER NOT NULL DEFAULT 0,sort_order INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS avx_transactions (id INTEGER PRIMARY KEY AUTOINCREMENT,profile_id INTEGER NOT NULL,type TEXT NOT NULL,amount INTEGER NOT NULL,reference TEXT,note TEXT,created_by_admin_email TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS idx_avx_transactions_profile_id ON avx_transactions(profile_id);

-- Job marketplace data.
CREATE TABLE IF NOT EXISTS jobs (id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,employer TEXT NOT NULL,location TEXT,work_mode TEXT,employment_type TEXT,required_skills TEXT,required_qualifications TEXT,required_certificates TEXT,min_experience INTEGER NOT NULL DEFAULT 0,apply_url TEXT,active INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS idx_jobs_active ON jobs(active);

-- Initial demo opportunities. They are examples, not guaranteed live vacancies.
INSERT INTO jobs(title,employer,location,work_mode,employment_type,required_skills,required_qualifications,required_certificates,min_experience,apply_url,active)
SELECT 'Software Developer','AVELIX Demo Employer','Remote','Remote','Full-time','JavaScript, Python, SQL, Git','B.Sc. Computer Science or related qualification','AWS or equivalent cloud certificate',1,'',1
WHERE NOT EXISTS (SELECT 1 FROM jobs WHERE title='Software Developer' AND employer='AVELIX Demo Employer');
INSERT INTO jobs(title,employer,location,work_mode,employment_type,required_skills,required_qualifications,required_certificates,min_experience,apply_url,active)
SELECT 'Mechanical Technician','AVELIX Demo Employer','Kaduna, Nigeria','Onsite','Full-time','Mechanical maintenance, CAD, troubleshooting','HND Mechanical Engineering or technical qualification','Trade certificate or relevant technical certificate',2,'',1
WHERE NOT EXISTS (SELECT 1 FROM jobs WHERE title='Mechanical Technician' AND employer='AVELIX Demo Employer');
INSERT INTO jobs(title,employer,location,work_mode,employment_type,required_skills,required_qualifications,required_certificates,min_experience,apply_url,active)
SELECT 'Project Manager','AVELIX Demo Employer','Hybrid','Hybrid','Full-time','Project management, communication, planning, Agile','B.Sc. or equivalent professional qualification','PMP or equivalent project certificate',3,'',1
WHERE NOT EXISTS (SELECT 1 FROM jobs WHERE title='Project Manager' AND employer='AVELIX Demo Employer');
INSERT INTO jobs(title,employer,location,work_mode,employment_type,required_skills,required_qualifications,required_certificates,min_experience,apply_url,active)
SELECT 'Marketing Specialist','AVELIX Demo Employer','Remote','Remote','Full-time','Digital marketing, social media, analytics, content','Marketing, Business, Communications or related qualification','Google Ads, Meta or equivalent certificate',1,'',1
WHERE NOT EXISTS (SELECT 1 FROM jobs WHERE title='Marketing Specialist' AND employer='AVELIX Demo Employer');
