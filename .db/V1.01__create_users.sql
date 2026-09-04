-- LOW: new empty table + index on that same new table.
CREATE TABLE users (
    id            BIGINT PRIMARY KEY,
    email         TEXT NOT NULL,
    status        TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_users_email ON users(email);
