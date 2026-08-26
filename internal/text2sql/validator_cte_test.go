package text2sql

import "testing"

// The validator accepts WITH as a query start, but the table check then measured
// the CTE's own name against the allow-list and rejected it as an unknown table.
// Every CTE failed for any subject with a table allow-list, even one reading
// only allowed tables.
func TestValidateSQLAllowsCTEOverAllowedTables(t *testing.T) {
	opts := ValidateOptions{AllowedTables: []string{"orders"}}
	for _, sql := range []string{
		"WITH c AS (SELECT id FROM orders) SELECT id FROM c",
		"WITH RECURSIVE c AS (SELECT id FROM orders) SELECT id FROM c",
		"WITH a AS (SELECT id FROM orders), b AS (SELECT id FROM a) SELECT id FROM b",
		"WITH c AS (SELECT id FROM orders) SELECT id FROM c JOIN orders o ON o.id = c.id",
	} {
		if got := ValidateSQL(sql, opts); !got.OK {
			t.Fatalf("ValidateSQL(%q) rejected a CTE over allowed tables: %s (tables=%v)", sql, got.Reason, got.Tables)
		}
	}
}

// A CTE body still has its real tables checked — the name is skipped, not the
// contents.
func TestValidateSQLChecksTablesInsideCTEBodies(t *testing.T) {
	opts := ValidateOptions{AllowedTables: []string{"orders"}}
	for _, sql := range []string{
		"WITH c AS (SELECT id FROM salaries) SELECT id FROM c",
		"WITH a AS (SELECT id FROM orders), b AS (SELECT id FROM salaries) SELECT id FROM b",
		"WITH c AS (SELECT id FROM orders, salaries) SELECT id FROM c",
	} {
		if got := ValidateSQL(sql, opts); got.OK {
			t.Fatalf("ValidateSQL(%q) allowed a restricted table inside a CTE: tables=%v", sql, got.Tables)
		}
	}
}

// A CTE that shadows a restricted table name is still safe: the shadowed name
// resolves to the CTE, and whatever the CTE actually reads is checked.
func TestValidateSQLHandlesCTEShadowingARestrictedName(t *testing.T) {
	opts := ValidateOptions{AllowedTables: []string{"orders"}}
	if got := ValidateSQL("WITH salaries AS (SELECT 1 AS x) SELECT x FROM salaries", opts); !got.OK {
		t.Fatalf("a CTE reading no base table was rejected: %s (tables=%v)", got.Reason, got.Tables)
	}
	if got := ValidateSQL("WITH salaries AS (SELECT id FROM salaries) SELECT id FROM salaries", opts); got.OK {
		t.Fatal("a CTE whose body reads a restricted table was allowed")
	}
}
