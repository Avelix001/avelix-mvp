-- AVELYX Digital CV data layer. Safe to run once; the Worker also creates this table automatically if needed.
CREATE TABLE IF NOT EXISTS digital_cv_data (
  profile_id INTEGER PRIMARY KEY,
  soft_skills TEXT,
  hard_skills TEXT,
  education TEXT,
  nysc TEXT,
  awards TEXT,
  work_experience TEXT,
  professional_certifications TEXT,
  summary TEXT,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);
