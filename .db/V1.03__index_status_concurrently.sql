-- MEDIUM: concurrent index build on an existing (populated) table.
CREATE INDEX CONCURRENTLY idx_users_status ON users(status);
