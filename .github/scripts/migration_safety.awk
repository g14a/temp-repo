# Database migration resource-spike analyzer (PostgreSQL). Pure awk, no deps.
#
# Static analysis of migration SQL. Flags operations that could cause a
# significant production DB CPU / memory / I/O / workload / lock spike because
# they do expensive work against EXISTING data. Cheap DDL (new table, add/drop
# column, index on a table created in the same migration) is LOW on purpose.
#
# Usage:
#   awk -f migration_safety.awk file1.sql file2.sql ...
# Writes a Markdown report to stdout. Writes the overall risk (LOW|MEDIUM|HIGH)
# to the file named by env RISK_FILE, if set.
#
# Portable: uses only POSIX awk features (no gensub/asort). Comment/string
# handling is conservative static analysis (documented limitation).

function rank(r) { if (r=="HIGH") return 2; if (r=="MEDIUM") return 1; return 0 }

# Return the token following the first occurrence of `kw` in string `s` (upper).
function token_after(s, kw,   m, rest, arr, n) {
    if (match(s, kw) == 0) return ""
    rest = substr(s, RSTART + RLENGTH)
    sub(/^ +/, "", rest)
    # first whitespace/paren/(-delimited token
    if (match(rest, /[^ (,;]+/)) return substr(rest, RSTART, RLENGTH)
    return ""
}

function is_new_table(name) { return (name in NEW) }

# add a finding for the current file
function add(risk, op, reason, impact, rec) {
    FN_RISK[FILES] = FN_RISK[FILES]  # ensure key
    N++
    F_FILE[N]=CURFILE; F_RISK[N]=risk; F_OP[N]=op; F_REASON[N]=reason
    F_IMPACT[N]=impact; F_REC[N]=rec
    if (rank(risk) > rank(FILERISK)) FILERISK=risk
    if (rank(risk) > rank(OVERALL)) OVERALL=risk
}

# ---- accumulate file contents, strip comments ----
FNR==1 {
    if (CURFILE != "") flush_file()
    CURFILE = FILENAME
    BUF = ""
    INBLOCK = 0
    FILERISK = "LOW"
    delete NEW
    delete ADDED
}
{
    line = $0
    # block comments /* ... */ (single-line and across lines)
    while (1) {
        if (INBLOCK) {
            p = index(line, "*/")
            if (p == 0) { line = ""; break }
            line = substr(line, p+2); INBLOCK = 0
        }
        s = index(line, "/*")
        if (s == 0) break
        e = index(substr(line, s+2), "*/")
        if (e == 0) { line = substr(line, 1, s-1); INBLOCK = 1; break }
        line = substr(line, 1, s-1) " " substr(line, s+2+e+1)
    }
    # line comment --
    d = index(line, "--")
    if (d) line = substr(line, 1, d-1)
    BUF = BUF " " line
}

function flush_file(   n, stmts, i, stmt, U, tbl, wh, setc, src, srcs, j, agg, arr) {
    n = split(BUF, stmts, ";")
    for (i = 1; i <= n; i++) {
        stmt = stmts[i]
        U = toupper(stmt)
        gsub(/[ \t\n]+/, " ", U)
        sub(/^ +/, "", U); sub(/ +$/, "", U)
        if (U == "") continue
        classify(stmt, U)
    }
}

function classify(stmt, U,   tbl, wh, setc, srcs, n, j, agg, colname) {

    # CREATE TABLE -> register empty table, LOW
    if (U ~ /^CREATE (GLOBAL |LOCAL )?(TEMP |TEMPORARY |UNLOGGED )*TABLE /) {
        tbl = token_after(U, "TABLE ")
        if (tbl == "IF") tbl = token_after(U, "NOT EXISTS ")
        gsub(/"/, "", tbl)
        if (tbl != "") NEW[tolower(tbl)] = 1
        return
    }

    # CREATE INDEX
    if (U ~ /^CREATE (UNIQUE )?INDEX /) {
        tbl = token_after(U, " ON ")
        if (tbl == "ONLY") tbl = token_after(U, " ON ONLY ")
        gsub(/"/, "", tbl); tbl = tolower(tbl)
        if (is_new_table(tbl)) return   # index on fresh empty table -> LOW
        # Policy: EVERY index on an existing table is flagged HIGH (blocks),
        # concurrent or not. Only an index on a table created in the same
        # migration file (handled above) is exempt.
        if (U ~ /CONCURRENTLY/) {
            add("HIGH", "CREATE INDEX CONCURRENTLY ON " tbl,
                "Index build on an existing table (full scan). Policy blocks all indexes on existing tables.",
                "High CPU, memory, I/O; query latency during build",
                "DevOps review. Run off-peak, monitor I/O.")
            return
        }
        add("HIGH", "CREATE INDEX ON " tbl,
            "Index build on an existing table takes an ACCESS EXCLUSIVE lock and scans every row.",
            "High CPU, memory, I/O; blocks writes",
            "Use CREATE INDEX CONCURRENTLY. DevOps review.")
        return
    }

    # ALTER TABLE
    if (U ~ /^ALTER TABLE /) {
        tbl = token_after(U, "ALTER TABLE ")
        if (tbl == "ONLY") tbl = token_after(U, "ALTER TABLE ONLY ")
        if (tbl == "IF") tbl = token_after(U, "IF EXISTS ")
        gsub(/"/, "", tbl); tbl = tolower(tbl)
        # track added column names for backfill detection
        if (match(U, /ADD COLUMN (IF NOT EXISTS )?[A-Z0-9_"]+/)) {
            colname = token_after(U, "ADD COLUMN ")
            if (colname == "IF") colname = token_after(U, "NOT EXISTS ")
            gsub(/"/, "", colname); ADDED[tolower(colname)] = 1
        }
        if (is_new_table(tbl)) return   # altering fresh empty table -> LOW
        if (U ~ /ALTER (COLUMN )?[A-Z0-9_"]+ (SET DATA )?TYPE /) {
            add("HIGH", "ALTER TABLE " tbl " ALTER COLUMN ... TYPE",
                "Type change can rewrite the whole table under an exclusive lock.",
                "High CPU, I/O; large WAL; exclusive lock",
                "Add new column, backfill in batches, then swap.")
            return
        }
        if (U ~ /SET NOT NULL/) {
            add("MEDIUM", "ALTER TABLE " tbl " SET NOT NULL",
                "NOT NULL scans the whole table to validate rows.",
                "Full table scan; exclusive lock",
                "CHECK (col IS NOT NULL) NOT VALID, VALIDATE, then SET NOT NULL (PG12+).")
            return
        }
        if (U ~ /ADD COLUMN/ && U ~ /DEFAULT /  && U ~ /(NOW\(|CURRENT_TIMESTAMP|RANDOM\(|GEN_RANDOM_UUID|UUID_GENERATE|CLOCK_TIMESTAMP|NEXTVAL)/) {
            add("MEDIUM", "ALTER TABLE " tbl " ADD COLUMN ... DEFAULT <volatile>",
                "Non-constant DEFAULT is evaluated per row, rewriting the table.",
                "High CPU, I/O; large WAL",
                "Add column without default, backfill in batches, then set default.")
            return
        }
        # ADD/DROP COLUMN, SET DEFAULT, RENAME, etc. -> LOW
        return
    }

    # UPDATE
    if (U ~ /^UPDATE /) {
        tbl = token_after(U, "UPDATE "); if (tbl=="ONLY") tbl=token_after(U,"UPDATE ONLY ")
        gsub(/"/, "", tbl); tbl = tolower(tbl)
        wh = where_clause(U)
        setc = U; sub(/^.* SET /, "", setc); sub(/ WHERE .*/, "", setc)
        agg = (setc ~ /SELECT / || setc ~ /(SUM|COUNT|AVG|MAX|MIN|JOIN)/)
        if (wh == "") {
            add("HIGH", "UPDATE " tbl,
                "Full-table UPDATE, no WHERE; every row modified.",
                "High CPU, I/O; large WAL; DB latency",
                "Backfill in batches keyed by primary key.")
            return
        }
        if (single_row(wh)) return
        if (agg) {
            add("HIGH", "UPDATE " tbl " (computed)",
                "UPDATE with a subquery/aggregation in SET over an existing table.",
                "High CPU, I/O; large WAL; memory for sort",
                "Precompute into a staging table, batch-apply by primary key.")
            return
        }
        add("MEDIUM", "UPDATE " tbl,
            "Broad UPDATE; predicate may match a large share of the table.",
            "High CPU, I/O; large WAL",
            "Confirm row estimate; batch by primary key if large.")
        return
    }

    # DELETE
    if (U ~ /^DELETE /) {
        tbl = token_after(U, "FROM "); if (tbl=="ONLY") tbl=token_after(U,"FROM ONLY ")
        gsub(/"/, "", tbl); tbl = tolower(tbl)
        wh = where_clause(U)
        if (wh == "") {
            add("HIGH", "DELETE FROM " tbl,
                "Full-table DELETE, no WHERE; every row deleted.",
                "High CPU, I/O; large WAL; DB latency",
                "Use TRUNCATE to clear, else delete in batches.")
            return
        }
        if (single_row(wh)) return
        add("MEDIUM", "DELETE FROM " tbl,
            "Range DELETE; may remove many rows.",
            "High CPU, I/O; large WAL",
            "Delete in bounded batches (WHERE ... LIMIT N).")
        return
    }

    # INSERT ... SELECT
    if (U ~ /^INSERT /) {
        if (U !~ /SELECT/) return          # INSERT ... VALUES -> LOW
        tbl = token_after(U, "INTO "); gsub(/"/, "", tbl); tbl = tolower(tbl)
        n = from_tables(U, srcs)
        existing = 0
        for (j = 1; j <= n; j++) if (!is_new_table(srcs[j])) existing = 1
        if (!existing) return              # SELECT from fresh/empty tables -> LOW
        agg = (U ~ /(GROUP BY|ORDER BY|DISTINCT|JOIN| SUM\(| COUNT\(| AVG\()/)
        add("HIGH", "INSERT INTO " tbl " SELECT ...",
            "INSERT ... SELECT reads existing table(s)" (agg ? " with aggregation/sort/join" : "") "; large scan and write.",
            "High CPU, I/O; large WAL" (agg ? "; memory for sort" : ""),
            "Populate in batches, or transform offline and load incrementally.")
        return
    }
    # everything else -> LOW
}

function where_clause(U,   p) {
    p = index(U, " WHERE ")
    if (p == 0) return ""
    return substr(U, p + 7)
}

# single (or few) row op: id-like column = literal/param, no OR, no range
function single_row(wh) {
    if (wh ~ / OR /) return 0
    if (wh ~ /[<>]/ || wh ~ / BETWEEN / || wh ~ / LIKE / || wh ~ / IN /) return 0
    if (wh ~ /(^| |\.)[A-Z0-9_]*ID *= *([0-9]+|'[^']*'|:[A-Z0-9_]+|[$][0-9]+|[?])/) return 1
    return 0
}

function from_tables(U, arr,   tmp, n, i, parts, k, m) {
    n = 0
    tmp = U
    while (match(tmp, /(FROM|JOIN) [A-Z0-9_."]+/)) {
        m = substr(tmp, RSTART, RLENGTH)
        sub(/^(FROM|JOIN) /, "", m)
        gsub(/"/, "", m)
        n++; arr[n] = tolower(m)
        tmp = substr(tmp, RSTART + RLENGTH)
    }
    return n
}

END {
    if (CURFILE != "") flush_file()

    # ---- render report (compact, one line per finding) ----
    print "## Database Migration Safety"
    if (OVERALL == "" || OVERALL == "LOW") {
        print "✅ PASS. No migration risks a production resource spike."
    } else if (OVERALL == "HIGH") {
        print "❌ HIGH risk. This PR is blocked."
    } else {
        print "⚠️ WARNING. Review recommended (not blocking)."
    }
    print ""
    for (k = 1; k <= N; k++) {
        emoji = (F_RISK[k]=="HIGH" ? "❌" : (F_RISK[k]=="MEDIUM" ? "⚠️" : "✅"))
        print "- " emoji " " F_RISK[k] " `" F_FILE[k] "`: `" F_OP[k] "`. " F_REASON[k] " Impact: " F_IMPACT[k] ". Fix: " F_REC[k]
    }
    lvl = (OVERALL == "" ? "LOW" : OVERALL)
    if (ENVIRON["RISK_FILE"] != "") print lvl > ENVIRON["RISK_FILE"]
}
