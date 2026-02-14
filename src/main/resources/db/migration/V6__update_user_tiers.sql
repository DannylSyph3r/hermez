-- Update tier constraint to use new subscription tiers
ALTER TABLE users DROP CONSTRAINT valid_tier;

ALTER TABLE users ADD CONSTRAINT valid_tier
    CHECK (tier IN ('chelys', 'inventor', 'petasos', 'talaria'));