CREATE TABLE users (
    username TEXT PRIMARY KEY NOT NULL COLLATE NOCASE,
    created_at INTEGER NOT NULL, -- unix ts
    email TEXT NOT NULL,
    invite_key TEXT,

    -- private
    password_hash TEXT NOT NULL,

    UNIQUE(username),
    UNIQUE(invite_key)
) STRICT;

CREATE TABLE services (
    name TEXT PRIMARY KEY NOT NULL COLLATE NOCASE,
    nice_name TEXT NOT NULL,
    id TEXT NOT NULL,
    description TEXT NOT NULL,
    secret TEXT NOT NULL,
    callback_url TEXT NOT NULL
) STRICT;

CREATE TABLE roles (
    name TEXT NOT NULL,
    service TEXT NOT NULL COLLATE NOCASE,

    FOREIGN KEY(service) REFERENCES services(name)
) STRICT;

CREATE TABLE user_roles (
    username TEXT NOT NULL COLLATE NOCASE,
    service TEXT NOT NULL,
    role TEXT NOT NULL,

    FOREIGN KEY(username) REFERENCES users(username),
    FOREIGN KEY(service) REFERENCES services(name),
    FOREIGN KEY(role) REFERENCES roles(name)
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

CREATE TABLE user_invite_default_roles (
    key TEXT NOT NULL,
    service TEXT NOT NULL,
    role TEXT NOT NULL,

    FOREIGN KEY(service) REFERENCES services(name),
    FOREIGN KEY(role) REFERENCES roles(name)
) STRICT;

-- bootstrap ourselves as a service
INSERT INTO services (name, nice_name, description, id, secret, callback_url) VALUES ('idbin', 'HiveID', 'Manage Hivecom accounts', '', 'aHVudGVyMg==', '/auth/authorize');
INSERT INTO roles (name, service) VALUES ('admin', 'idbin');

INSERT INTO user_invites (key, created_by, created_at, services) VALUES ('admin', 'admin', 0, 'admin');
INSERT INTO user_invite_default_roles (key, service, role) VALUES ('admin', 'idbin', 'admin');
