-- Create users table
CREATE TABLE users (
                       id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                       email VARCHAR(255) NOT NULL UNIQUE,
                       password_hash VARCHAR(255),
                       name VARCHAR(255),
                       avatar_url VARCHAR(500),
                       tier VARCHAR(20) NOT NULL DEFAULT 'free',
                       created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                       updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                       last_login_at TIMESTAMP WITH TIME ZONE,

                       CONSTRAINT valid_tier CHECK (tier IN ('free', 'paid', 'admin'))
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_created_at ON users(created_at);

-- Create oauth_connections table
CREATE TABLE oauth_connections (
                                   id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                                   user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                                   provider VARCHAR(50) NOT NULL,
                                   provider_id VARCHAR(255) NOT NULL,
                                   access_token TEXT,
                                   refresh_token TEXT,
                                   token_expires_at TIMESTAMP WITH TIME ZONE,
                                   created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

                                   UNIQUE(provider, provider_id)
);

CREATE INDEX idx_oauth_connections_user_id ON oauth_connections(user_id);

-- Create trigger function for updated_at
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger on users table
CREATE TRIGGER users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at();