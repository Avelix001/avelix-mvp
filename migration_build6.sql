-- AVELIX Build 6 migration: profile levels, card tiers and upgrade architecture.
-- Run ONCE against the existing avelix-db after Build 5.
ALTER TABLE profiles ADD COLUMN card_tier TEXT NOT NULL DEFAULT 'basic';
UPDATE profiles SET account_type='individual', card_tier='basic' WHERE account_type IS NULL OR account_type NOT IN ('individual','entrepreneur','business');
UPDATE profiles SET card_tier=CASE account_type WHEN 'business' THEN 'gold' WHEN 'entrepreneur' THEN 'platinum' ELSE 'basic' END;
CREATE INDEX IF NOT EXISTS idx_profiles_card_tier ON profiles(card_tier);
