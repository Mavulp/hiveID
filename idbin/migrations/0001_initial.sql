CREATE TABLE users (
    username TEXT PRIMARY KEY NOT NULL COLLATE NOCASE,
    created_at INTEGER NOT NULL, -- unix ts
    email TEXT NOT NULL,
    invite_key TEXT,

    -- private
    password_hash TEXT NOT NULL,

    UNIQUE(invite_key)
) STRICT;

CREATE TABLE audit_logs (
    action TEXT NOT NULL,
    performed_by TEXT NOT NULL COLLATE NOCASE,
    at INTEGER NOT NULL
) STRICT;

CREATE INDEX idx_audit_logs_at
ON audit_logs (at);

CREATE TABLE user_invites (
    key TEXT PRIMARY KEY NOT NULL,
    created_by TEXT NOT NULL,
    created_at INTEGER NOT NULL, -- unix ts

    services TEXT NOT NULL
) STRICT;

INSERT INTO user_invites (key, created_by, created_at, services) VALUES ('admin', 'admin', 0, 'admin');
