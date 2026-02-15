-- Drop old constraint
ALTER TABLE users DROP CONSTRAINT valid_tier;

-- Update existing users to new tier names
UPDATE users SET tier = 'chelys' WHERE tier = 'free';
UPDATE users SET tier = 'inventor' WHERE tier = 'paid';
UPDATE users SET tier = 'talaria' WHERE tier = 'admin';

-- Change DEFAULT from 'free' to 'chelys'
ALTER TABLE users ALTER COLUMN tier SET DEFAULT 'chelys';

-- Add new constraint
ALTER TABLE users ADD CONSTRAINT valid_tier
    CHECK (tier IN ('chelys', 'inventor', 'petasos', 'talaria'));