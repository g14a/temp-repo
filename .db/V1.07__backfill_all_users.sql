-- HIGH: full-table backfill with no WHERE — rewrites every existing row.
UPDATE users
SET status = 'active';
