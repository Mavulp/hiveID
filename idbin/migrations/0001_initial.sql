CREATE TABLE users (
    username TEXT PRIMARY KEY NOT NULL COLLATE NOCASE,
    display_name TEXT NULL,
    created_at INTEGER NOT NULL, -- unix ts

    -- private
    password_hash TEXT NOT NULL
) STRICT;
