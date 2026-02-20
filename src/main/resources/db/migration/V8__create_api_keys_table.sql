CREATE TABLE api_keys (
                          id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                          user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                          name         VARCHAR(255) NOT NULL,
                          key_hash     VARCHAR(255) NOT NULL UNIQUE,
                          key_preview  VARCHAR(50)  NOT NULL,
                          created_at   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                          last_used_at TIMESTAMP WITH TIME ZONE,
                          revoked_at   TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_api_keys_user_id  ON api_keys(user_id);
CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash);
CREATE UNIQUE INDEX idx_api_keys_user_id_name_active
    ON api_keys (user_id, name)
    WHERE revoked_at IS NULL;