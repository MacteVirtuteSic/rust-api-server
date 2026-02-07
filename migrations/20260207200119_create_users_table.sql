--- 1. Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "citext";

-- 2. Create the Table
CREATE TABLE users (
    -- Use UUID v4 for security and distributed systems compatibility
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Case-insensitive text prevents "Admin" and "admin" from being different users
    username CITEXT NOT NULL UNIQUE,
    email CITEXT NOT NULL UNIQUE,

    -- Ensure password field is long enough for Argon2/BCrypt hashes
    password_hash VARCHAR(255) NOT NULL,

    superuser BOOLEAN NOT NULL DEFAULT FALSE,

    -- TIMESTAMPTZ is mandatory for production to avoid timezone confusion
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Constraint: Prevent empty strings and basic email validation
    CONSTRAINT username_length_check CHECK (char_length(username) >= 3),
    CONSTRAINT email_valid_check CHECK (email ~* '^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$')
);

-- 3. Optimization: Index for common lookups
-- Since email is UNIQUE, Postgres already creates an index,
-- but we might want a specific index for sorting by join date.
CREATE INDEX idx_users_created_at ON users(created_at);

-- 4. Re-use your existing Trigger logic
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
