-- LOW: metadata-only column add (no default rewrite), plus a single-row update.
ALTER TABLE users ADD COLUMN nickname TEXT;

UPDATE users SET nickname = 'admin' WHERE id = 1;

-- feature tweak
