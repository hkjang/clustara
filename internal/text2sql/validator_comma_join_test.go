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
