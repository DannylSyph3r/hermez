CREATE TABLE custom_domains (
                                id                 UUID                     PRIMARY KEY DEFAULT gen_random_uuid(),
                                user_id            UUID                     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                                domain             VARCHAR(253)             NOT NULL UNIQUE,
                                linked_subdomain   VARCHAR(63)              NOT NULL,
                                status             VARCHAR(20)              NOT NULL DEFAULT 'pending',
                                verification_token VARCHAR(64)              NOT NULL,
                                verified_at        TIMESTAMP WITH TIME ZONE,
                                created_at         TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                                updated_at         TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

                                CONSTRAINT custom_domains_status_check CHECK (status IN ('pending', 'verified', 'active', 'failed'))
);

CREATE INDEX idx_custom_domains_user_id ON custom_domains(user_id);
CREATE INDEX idx_custom_domains_status ON custom_domains(status);

CREATE TRIGGER custom_domains_updated_at
    BEFORE UPDATE ON custom_domains
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at();