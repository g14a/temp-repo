-- LOW: brand-new empty table + index on that same new table.
CREATE TABLE audit_log (
    id    BIGINT PRIMARY KEY,
    note  TEXT
);
CREATE INDEX idx_audit_log_note ON audit_log(note);
