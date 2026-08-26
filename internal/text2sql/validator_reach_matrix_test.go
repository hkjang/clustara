package text2sql

import "testing"

// These are the query shapes that reach a restricted table without necessarily
// naming it in an obvious position. Four bypasses in this family were fixed in
// v0.9.177-v0.9.178 (comma join, parenthesised join, wildcard select for blocked
// and for aggregate-only columns); this matrix keeps the whole family closed.
func TestRestrictedTableIsUnreachable(t *testing.T) {
	opts := ValidateOptions{AllowedTables: []string{"orders"}}
	for _, sql := range []string{
		"SELECT x FROM salaries",
		"SELECT x FROM public.salaries",
		`SELECT x FROM "salaries"`,
		"SELECT x FROM SaLaRiEs",
		"SELECT x FROM salaries AS s",
		"SELECT x FROM orders WHERE id IN (SELECT id FROM salaries)",
		"SELECT (SELECT max(x) FROM salaries) FROM orders",
		"SELECT x FROM orders UNION SELECT x FROM salaries",
		"SELECT x FROM orders INTERSECT SELECT x FROM salaries",
		"SELECT x FROM orders EXCEPT SELECT x FROM salaries",
		"WITH c AS (SELECT x FROM salaries) SELECT x FROM c",
		"SELECT 1 FROM orders WHERE EXISTS (SELECT 1 FROM salaries)",
		"SELECT x FROM orders o LEFT JOIN salaries s ON o.id=s.id",
		"SELECT x FROM orders, LATERAL (SELECT x FROM salaries) z",
	} {
		if got := ValidateSQL(sql, opts); got.OK {
			t.Errorf("restricted table reached by: %q tables=%v", sql, got.Tables)
		}
	}
}

// The column equivalent: every shape that returns a restricted column, whether
// it names the column or not.
func TestRestrictedColumnIsUnreachable(t *testing.T) {
	opts := ValidateOptions{AllowedTables: []string{"employees"}, BlockedColumns: []string{"salary"}}
	for _, sql := range []string{
		"SELECT salary FROM employees",
		"SELECT SALARY FROM employees",
		"SELECT e.salary FROM employees e",
		`SELECT "salary" FROM employees`,
		"SELECT salary AS s FROM employees",
		"SELECT upper(salary) FROM employees",
		"SELECT id FROM employees WHERE salary > 100",
		"SELECT id FROM employees ORDER BY salary",
		"SELECT id FROM employees GROUP BY salary",
		"SELECT * FROM employees",
		"SELECT e.* FROM employees e",
		"SELECT id FROM employees WHERE id IN (SELECT id FROM employees WHERE salary > 1)",
		"WITH c AS (SELECT salary AS s FROM employees) SELECT s FROM c",
	} {
		if got := ValidateSQL(sql, opts); got.OK {
			t.Errorf("restricted column reached by: %q", sql)
		}
	}
}
