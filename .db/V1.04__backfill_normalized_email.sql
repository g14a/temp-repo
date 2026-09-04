-- HIGH: large backfill — add a column then update every existing row.
ALTER TABLE users ADD COLUMN normalized_email TEXT;

UPDATE users
SET normalized_email = LOWER(email);
