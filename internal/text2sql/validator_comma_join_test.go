package text2sql

import "testing"

// The table allow-list is the mechanism that restricts which tables a subject may
// read. fromJoin only captured the first source after FROM, so a comma-separated
// list read a second table that was never extracted and therefore never checked.
func TestValidateSQLChecksCommaJoinedSources(t *testing.T) {
	opts := ValidateOptions{AllowedTables: []string{"orders"}}
	for _, sql := range []string{
		"SELECT * FROM orders, salaries",
		"SELECT * FROM orders o, salaries s WHERE o.id = s.id",
		"SELECT * FROM orders AS o, salaries AS s WHERE o.id = s.id",
		"SELECT * FROM orders, public.salaries",
		`SELECT * FROM orders, "Salaries"`,
		"SELECT * FROM orders a, orders b, salaries c",
	} {
		got := ValidateSQL(sql, opts)
		if got.OK {
			t.Fatalf("ValidateSQL(%q) allowed a table outside the allow-list: tables=%v", sql, got.Tables)
		}
	}
}

// Every source in the list has to be reported, not just the offending one — the
// extracted set is also what callers audit.
func TestReferencedTablesReportsEverySource(t *testing.T) {
	got := referencedTables("select * from orders o, salaries s, public.payroll p")
	want := map[string]bool{"orders": true, "salaries": true, "public.payroll": true}
	if len(got) != len(want) {
		t.Fatalf("referencedTables = %v, want %d sources", got, len(want))
	}
	for _, g := range got {
		if !want[g] {
			t.Fatalf("referencedTables = %v, unexpected %q", got, g)
		}
	}
}

// A comma-joined list of allowed tables must still pass, and the walk must stop
// at a following clause rather than swallowing it.
func TestValidateSQLAllowsCommaJoinWithinTheAllowList(t *testing.T) {
	opts := ValidateOptions{AllowedTables: []string{"orders", "customers"}}
	for _, sql := range []string{
		"SELECT * FROM orders, customers",
		"SELECT * FROM orders o, customers c WHERE o.id = c.id",
		"SELECT * FROM orders WHERE id IN (SELECT id FROM customers)",
	} {
		if got := ValidateSQL(sql, opts); !got.OK {
			t.Fatalf("ValidateSQL(%q) rejected an allowed query: %s (tables=%v)", sql, got.Reason, got.Tables)
		}
	}
}

// A select list comma must not be mistaken for a source separator.
func TestReferencedTablesIgnoresNonSourceCommas(t *testing.T) {
	got := referencedTables("select a, b, c from orders where x in (1, 2, 3)")
	if len(got) != 1 || got[0] != "orders" {
		t.Fatalf("referencedTables = %v, want just [orders]", got)
	}
}

// fromJoin required the source to directly follow FROM/JOIN, so a parenthesised
// join's first source was preceded by "(" and never extracted — and an
// unextracted source is never checked against the allow-list.
func TestValidateSQLChecksParenthesisedJoinSources(t *testing.T) {
	opts := ValidateOptions{AllowedTables: []string{"orders"}}
	for _, sql := range []string{
		"SELECT * FROM (salaries JOIN orders ON 1=1) x",
		"SELECT * FROM (salaries CROSS JOIN orders) x",
		"SELECT * FROM ((salaries JOIN orders ON 1=1)) x",
		"SELECT * FROM ONLY salaries",
	} {
		if got := ValidateSQL(sql, opts); got.OK {
			t.Fatalf("ValidateSQL(%q) allowed a table outside the allow-list: tables=%v", sql, got.Tables)
		}
	}
}

// The extracted set is what callers audit, so a Postgres ONLY/LATERAL prefix
// must not be reported as the table name.
func TestReferencedTablesSkipsSourcePrefixes(t *testing.T) {
	for _, tc := range []struct {
		sql  string
		want string
	}{
		{"select * from only salaries", "salaries"},
		{"select * from lateral (select * from salaries) s", "salaries"},
		{"select * from (salaries join orders on 1=1) x", "salaries"},
	} {
		got := referencedTables(tc.sql)
		if len(got) == 0 || got[0] != tc.want {
			t.Fatalf("referencedTables(%q) = %v, want %q first", tc.sql, got, tc.want)
		}
	}
}

// A subquery source must not be reported as a table named "select"; the tables
// inside it are found by the same scan.
func TestReferencedTablesSkipsSubqueryKeywords(t *testing.T) {
	got := referencedTables("select * from (select id from orders) t")
	if len(got) != 1 || got[0] != "orders" {
		t.Fatalf("referencedTables = %v, want just [orders]", got)
	}
	opts := ValidateOptions{AllowedTables: []string{"orders"}}
	if res := ValidateSQL("SELECT * FROM (SELECT id FROM orders) t", opts); !res.OK {
		t.Fatalf("subquery over an allowed table was rejected: %s (tables=%v)", res.Reason, res.Tables)
	}
}
