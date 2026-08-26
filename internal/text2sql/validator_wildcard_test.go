package text2sql

import "testing"

// Naming a blocked column is rejected, but a wildcard returns it without ever
// naming it — and a wildcard is the shape a generator reaches for most often,
// so the restriction leaked on ordinary queries rather than adversarial ones.
func TestValidateSQLRejectsWildcardWhenColumnsRestricted(t *testing.T) {
	opts := ValidateOptions{AllowedTables: []string{"employees"}, BlockedColumns: []string{"salary"}}
	for _, sql := range []string{
		"SELECT * FROM employees",
		"SELECT e.* FROM employees e",
		"SELECT employees.* FROM employees",
		"SELECT id, * FROM employees",
		"SELECT *, id FROM employees",
	} {
		if got := ValidateSQL(sql, opts); got.OK {
			t.Fatalf("ValidateSQL(%q) allowed a wildcard while columns are restricted", sql)
		}
	}
}

// count(*) exposes no column values, and arithmetic is not a wildcard.
func TestValidateSQLKeepsAggregatesAndArithmetic(t *testing.T) {
	opts := ValidateOptions{AllowedTables: []string{"employees"}, BlockedColumns: []string{"salary"}}
	for _, sql := range []string{
		"SELECT count(*) FROM employees",
		"SELECT count(*) AS n FROM employees",
		"SELECT id, count(*) FROM employees GROUP BY id",
		"SELECT bonus * 2 FROM employees",
		"SELECT bonus*2 FROM employees",
		"SELECT id FROM employees",
	} {
		if got := ValidateSQL(sql, opts); !got.OK {
			t.Fatalf("ValidateSQL(%q) rejected a safe query: %s", sql, got.Reason)
		}
	}
}

// A subject with no restricted columns keeps SELECT * exactly as before.
func TestValidateSQLKeepsWildcardWhenNothingIsRestricted(t *testing.T) {
	opts := ValidateOptions{AllowedTables: []string{"employees"}}
	for _, sql := range []string{
		"SELECT * FROM employees",
		"SELECT e.* FROM employees e",
	} {
		if got := ValidateSQL(sql, opts); !got.OK {
			t.Fatalf("ValidateSQL(%q) rejected a wildcard with no restricted columns: %s", sql, got.Reason)
		}
	}
}
