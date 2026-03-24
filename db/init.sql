-- ============================================================
--  PacketPulse — Database Schema
--  Runs automatically on first Postgres container start.
--  Order matters: tables with foreign keys come after the
--  tables they reference.
-- ============================================================

-- ────────────────────────────────────────────────────────────
--  EXTENSIONS
--  pgcrypto gives us gen_random_uuid() for UUID primary keys.
--  Available in standard Postgres — no extra install needed.
-- ────────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ────────────────────────────────────────────────────────────
--  TABLE: users
--  One row per registered operator.
-- ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    -- Identity
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    operator_id     VARCHAR(40) NOT NULL UNIQUE,   -- the "username" used to sign in
    email           VARCHAR(255) NOT NULL UNIQUE,
    display_name    VARCHAR(120) NOT NULL,

    -- Auth
    password_hash   TEXT        NOT NULL,           -- bcrypt hash, never plain text
    totp_secret     TEXT,                           -- NULL until 2FA is set up
    totp_enabled    BOOLEAN     NOT NULL DEFAULT FALSE,

    -- Profile
    role            VARCHAR(30) NOT NULL DEFAULT 'other',
        -- allowed values: security | sysadmin | devops | other
    organisation    VARCHAR(120),
    network_scale   VARCHAR(20),
        -- allowed values: 1-10 | 11-50 | 51-200 | 200+

    -- Account state
    status          VARCHAR(20) NOT NULL DEFAULT 'pending',
        -- allowed values: pending | active | suspended
    failed_attempts INT         NOT NULL DEFAULT 0,  -- consecutive bad logins
    locked_until    TIMESTAMPTZ,                     -- NULL = not locked

    -- Audit
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at   TIMESTAMPTZ
);

-- Indexes used by auth lookups
CREATE INDEX IF NOT EXISTS idx_users_operator_id ON users (operator_id);
CREATE INDEX IF NOT EXISTS idx_users_email       ON users (email);
CREATE INDEX IF NOT EXISTS idx_users_status      ON users (status);

-- ────────────────────────────────────────────────────────────
--  TABLE: sessions
--  One row per active login session.
--  A user can have multiple sessions (different devices/tabs).
-- ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sessions (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash   TEXT        NOT NULL UNIQUE,  -- SHA-256 hash of the JWT; never the raw token
    ip_address   INET,                         -- IPv4 or IPv6 of the client
    user_agent   TEXT,                         -- browser / tool identifier
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked      BOOLEAN     NOT NULL DEFAULT FALSE,
    revoked_at   TIMESTAMPTZ                   -- NULL until explicitly revoked
);

-- Indexes: token lookup on every authenticated request (hot path)
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash  ON sessions (token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id     ON sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at  ON sessions (expires_at);

-- ────────────────────────────────────────────────────────────
--  TABLE: scans
--  Metadata record for each scan run.
--  One row per scan, regardless of how many hosts were found.
-- ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scans (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    -- Target definition
    subnet          VARCHAR(20) NOT NULL,   -- e.g. 192.168.1
    range_start     SMALLINT    NOT NULL,   -- 1–254
    range_end       SMALLINT    NOT NULL,   -- 1–254

    -- Port filter snapshot (comma-separated port numbers, NULL = all ports)
    ports_filter    TEXT,

    -- Outcome
    status          VARCHAR(20) NOT NULL DEFAULT 'running',
        -- allowed values: running | complete | failed
    hosts_scanned   INT         NOT NULL DEFAULT 0,
    hosts_alive     INT         NOT NULL DEFAULT 0,
    open_ports      INT         NOT NULL DEFAULT 0,
    duration_ms     INT,                    -- total scan duration in milliseconds

    -- Audit
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ             -- NULL while still running
);

-- Indexes: history queries filter and sort by user + time
CREATE INDEX IF NOT EXISTS idx_scans_user_id    ON scans (user_id);
CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans (started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_status     ON scans (status);

-- ────────────────────────────────────────────────────────────
--  TABLE: scan_hosts
--  One row per IP address evaluated in a scan.
--  Stores both dead hosts (is_up = FALSE) and live hosts.
-- ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_hosts (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id     UUID        NOT NULL REFERENCES scans (id) ON DELETE CASCADE,

    -- Host identity
    ip_address  INET        NOT NULL,
    hostname    VARCHAR(255),               -- reverse DNS result, NULL if none

    -- Result
    is_up       BOOLEAN     NOT NULL DEFAULT FALSE,

    -- Full port data stored as JSONB for flexibility.
    -- Shape: [{"port": 22, "label": "SSH", "category": "remote", "banner": "..."}, ...]
    ports       JSONB       NOT NULL DEFAULT '[]'::JSONB
);

-- Indexes: looking up hosts within a specific scan
CREATE INDEX IF NOT EXISTS idx_scan_hosts_scan_id    ON scan_hosts (scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_hosts_ip         ON scan_hosts (ip_address);
CREATE INDEX IF NOT EXISTS idx_scan_hosts_is_up      ON scan_hosts (is_up);

-- GIN index on the ports JSONB column enables fast queries like
-- "find all scans where port 445 was open" without scanning every row
CREATE INDEX IF NOT EXISTS idx_scan_hosts_ports_gin  ON scan_hosts USING GIN (ports);

-- ────────────────────────────────────────────────────────────
--  TABLE: login_attempts
--  Audit log of every sign-in attempt, successful or not.
--  Used for rate limiting, anomaly detection, and compliance.
--  Separate from sessions — a failed attempt creates no session.
-- ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS login_attempts (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    operator_id     VARCHAR(40) NOT NULL,   -- what was submitted (may not exist)
    ip_address      INET        NOT NULL,
    user_agent      TEXT,
    success         BOOLEAN     NOT NULL,
    failure_reason  VARCHAR(60),
        -- NULL on success; otherwise: 'bad_password' | 'user_not_found' |
        -- 'account_suspended' | 'account_pending' | 'account_locked' | 'bad_totp'
    attempted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes: rate-limit queries look up recent attempts by IP or operator_id
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip          ON login_attempts (ip_address);
CREATE INDEX IF NOT EXISTS idx_login_attempts_operator_id ON login_attempts (operator_id);
CREATE INDEX IF NOT EXISTS idx_login_attempts_attempted_at ON login_attempts (attempted_at DESC);

-- ────────────────────────────────────────────────────────────
--  FUNCTION + TRIGGER: auto-update updated_at on users
--  Keeps the updated_at column accurate without the app
--  needing to remember to set it manually on every UPDATE.
-- ────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();

-- ────────────────────────────────────────────────────────────
--  FUNCTION: clean_expired_sessions()
--  Call this on a schedule (e.g. daily) to purge sessions that
--  expired more than 30 days ago. Keeps the table lean.
-- ────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION clean_expired_sessions()
RETURNS INT AS $$
DECLARE
    deleted INT;
BEGIN
    DELETE FROM sessions
    WHERE expires_at < NOW() - INTERVAL '30 days';
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;

-- ────────────────────────────────────────────────────────────
--  FUNCTION: is_account_locked(p_operator_id)
--  Returns TRUE if the account is currently in a lockout window.
--  The backend calls this before checking the password so
--  locked accounts get rejected before a hash comparison.
-- ────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION is_account_locked(p_operator_id VARCHAR)
RETURNS BOOLEAN AS $$
DECLARE
    v_locked_until TIMESTAMPTZ;
BEGIN
    SELECT locked_until INTO v_locked_until
    FROM   users
    WHERE  operator_id = p_operator_id;

    IF NOT FOUND THEN
        RETURN FALSE;  -- unknown operator, handled elsewhere
    END IF;

    RETURN (v_locked_until IS NOT NULL AND v_locked_until > NOW());
END;
$$ LANGUAGE plpgsql;

-- ────────────────────────────────────────────────────────────
--  FUNCTION: record_failed_login(p_operator_id, p_threshold)
--  Increments failed_attempts. If the count hits p_threshold,
--  sets locked_until to 15 minutes from now.
--  Backend calls this after every bad-password rejection.
-- ────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION record_failed_login(
    p_operator_id VARCHAR,
    p_threshold   INT DEFAULT 5
)
RETURNS VOID AS $$
DECLARE
    v_attempts INT;
BEGIN
    UPDATE users
    SET    failed_attempts = failed_attempts + 1
    WHERE  operator_id = p_operator_id
    RETURNING failed_attempts INTO v_attempts;

    IF v_attempts >= p_threshold THEN
        UPDATE users
        SET    locked_until = NOW() + INTERVAL '15 minutes'
        WHERE  operator_id = p_operator_id
          AND (locked_until IS NULL OR locked_until < NOW());
    END IF;
END;
$$ LANGUAGE plpgsql;

-- ────────────────────────────────────────────────────────────
--  FUNCTION: clear_failed_logins(p_operator_id)
--  Resets the counter and removes the lock after a
--  successful sign-in.
-- ────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION clear_failed_logins(p_operator_id VARCHAR)
RETURNS VOID AS $$
BEGIN
    UPDATE users
    SET    failed_attempts = 0,
           locked_until    = NULL,
           last_login_at   = NOW()
    WHERE  operator_id = p_operator_id;
END;
$$ LANGUAGE plpgsql;

-- ────────────────────────────────────────────────────────────
--  SEED: default admin account
--  Password is 'Me_Admin1!Change' — must be rotated on first
--  login in any real deployment. The hash below was produced
--  by bcrypt with 12 rounds.
--  operator_id: pp_admin
-- ────────────────────────────────────────────────────────────
INSERT INTO users (
    operator_id,
    email,
    display_name,
    password_hash,
    role,
    status
)
VALUES (
    'pp_admin',
    'admin@packetpulse.local',
    'PacketPulse Admin',
    -- bcrypt hash of 'Me_Admin1!Change' 
    '$2b$12$CJS8t3rGLrltm.VhNR2TL.yaIgSuAFYraW/JmGAL3W3FR7xlTsICS',
    'admin',
    'active'
)
ON CONFLICT (operator_id) DO NOTHING;

-- ────────────────────────────────────────────────────────────
--  MIGRATION: email verification & password reset tokens
-- ────────────────────────────────────────────────────────────
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email_verified      BOOLEAN     NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS email_verify_token  VARCHAR(64),
    ADD COLUMN IF NOT EXISTS email_verify_expiry TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS pw_reset_token      VARCHAR(64),
    ADD COLUMN IF NOT EXISTS pw_reset_expiry     TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_users_email_verify_token ON users (email_verify_token);
CREATE INDEX IF NOT EXISTS idx_users_pw_reset_token     ON users (pw_reset_token);