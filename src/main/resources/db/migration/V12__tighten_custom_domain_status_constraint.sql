ALTER TABLE custom_domains DROP CONSTRAINT IF EXISTS custom_domains_status_check;

ALTER TABLE custom_domains ADD CONSTRAINT custom_domains_status_check
    CHECK (status IN ('pending', 'active', 'failed'));