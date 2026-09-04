-- YTMY-653: Index for Apple Pay report queries filtering by token PAN type
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pt_token_pan_type
  ON processor_transaction (token_pan_type, transaction_type, transaction_at)
  WHERE token_pan_type != '';
