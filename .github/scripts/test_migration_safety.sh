#!/usr/bin/env bash
# Tests for the awk migration-safety analyzer. Run: bash test_migration_safety.sh
# No dependencies beyond awk (same as CI). Exit 0 = all pass.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
AWK_SCRIPT="$HERE/migration_safety.awk"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fails=0

# check NAME "SQL" "EXPECTED [EXPECTED2 ...]"  — pass if actual risk is in the set
check() {
  local name="$1" sql="$2" expected="$3" actual ok=FAIL
  printf '%s\n' "$sql" > "$TMP/t.sql"
  RISK_FILE="$TMP/risk" awk -f "$AWK_SCRIPT" "$TMP/t.sql" >/dev/null 2>"$TMP/err"
  actual="$(cat "$TMP/risk" 2>/dev/null || echo '?')"
  case " $expected " in *" $actual "*) ok=PASS ;; esac
  printf '%-30s got=%-6s exp=%-12s %s\n' "$name" "$actual" "$expected" "$ok"
  if [[ "$ok" == FAIL ]]; then fails=$((fails+1)); [[ -s "$TMP/err" ]] && cat "$TMP/err"; fi
}

check full_update       "UPDATE users SET status='active';" "HIGH"
check broad_update_null "UPDATE users SET status='active' WHERE status IS NULL;" "HIGH MEDIUM"
check single_update_id  "UPDATE users SET status='active' WHERE id = 123;" "LOW"
check single_update_bind "UPDATE users SET status='active' WHERE id = :uid;" "LOW"
check backfill          $'ALTER TABLE users ADD COLUMN normalized_email TEXT;\nUPDATE users SET normalized_email = LOWER(email);' "HIGH"
check full_delete       "DELETE FROM users;" "HIGH"
check range_delete      "DELETE FROM events WHERE created_at < '2020-01-01';" "HIGH MEDIUM"
check single_delete     "DELETE FROM users WHERE id = 5;" "LOW"
check index_existing    "CREATE INDEX idx_users_email ON users(email);" "HIGH"
check index_concurrent  "CREATE INDEX CONCURRENTLY idx_users_email ON users(email);" "MEDIUM"
check index_new_table   $'CREATE TABLE foo (id BIGINT PRIMARY KEY, bar TEXT);\nCREATE INDEX idx_foo_bar ON foo(bar);' "LOW"
check agg_insert_select "INSERT INTO user_stats SELECT user_id, COUNT(*) FROM events GROUP BY user_id;" "HIGH"
check insert_new_table  $'CREATE TABLE staging (id BIGINT, v TEXT);\nINSERT INTO target SELECT id, v FROM staging;' "LOW"
check computed_update   "UPDATE accounts SET balance = (SELECT SUM(amount) FROM transactions WHERE transactions.account_id = accounts.id);" "HIGH"
check type_change       "ALTER TABLE users ALTER COLUMN amount TYPE NUMERIC(20,4);" "HIGH"
check set_not_null      "ALTER TABLE users ALTER COLUMN email SET NOT NULL;" "MEDIUM"
check create_table      "CREATE TABLE new_t (id BIGINT PRIMARY KEY, name TEXT);" "LOW"
check add_column        "ALTER TABLE users ADD COLUMN nickname TEXT;" "LOW"
check drop_column       "ALTER TABLE users DROP COLUMN nickname;" "LOW"
check insert_values     "INSERT INTO config (k,v) VALUES ('x','on');" "LOW"
check comments          $'-- backfill\nUPDATE users SET status=\'active\' WHERE id = 1; -- one row' "LOW"

echo
if [[ "$fails" -eq 0 ]]; then echo "All tests passed."; else echo "$fails test(s) FAILED."; exit 1; fi
