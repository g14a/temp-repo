-- LOW: new empty table + index on that same table.
CREATE TABLE promo (id BIGINT PRIMARY KEY, code TEXT);
CREATE INDEX idx_promo_code ON promo(code);
