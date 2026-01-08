-- Create subdomain_reservations table
CREATE TABLE subdomain_reservations (
                                        subdomain VARCHAR(63) PRIMARY KEY,
                                        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                                        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                                        expires_at TIMESTAMP WITH TIME ZONE,

                                        CONSTRAINT valid_subdomain CHECK (
                                            subdomain ~ '^[a-z][a-z0-9-]{1,61}[a-z0-9]$'
                                            OR subdomain ~ '^[a-z][a-z0-9]?$'
)
    );

CREATE INDEX idx_subdomain_reservations_user_id ON subdomain_reservations(user_id);
CREATE INDEX idx_subdomain_reservations_expires_at ON subdomain_reservations(expires_at);