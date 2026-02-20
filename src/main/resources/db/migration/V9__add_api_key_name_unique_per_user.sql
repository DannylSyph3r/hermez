CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_user_id_name_active
    ON api_keys (user_id, name)
    WHERE revoked_at IS NULL;