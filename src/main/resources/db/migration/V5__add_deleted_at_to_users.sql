-- Add deletedAt column to users table for soft delete functionality
ALTER TABLE users ADD COLUMN deleted_at TIMESTAMP WITH TIME ZONE;

-- Create index for soft delete queries
CREATE INDEX idx_users_deleted_at ON users(deleted_at);