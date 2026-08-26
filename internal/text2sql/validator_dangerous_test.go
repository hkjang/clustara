package text2sql

import "testing"

// The denylist is matched as substrings, so entries that named one function
// exactly missed its near neighbours: pg_read_binary_file does not contain
// "pg_read_file", and pg_ls_logdir does not contain "pg_ls_dir".
func TestValidateSQLRejectsFileAndDirFunctionFamilies(t *testing.T) {
	for _, sql := range []string{
		"SELECT pg_read_file('/etc/passwd')",
		"SELECT pg_read_binary_file('/etc/passwd')",
		"SELECT pg_ls_dir('/')",
		"SELECT pg_ls_logdir()",
		"SELECT pg_ls_waldir()",
		"SELECT pg_stat_file('/etc/passwd')",
		"SELECT lo_get(1)",
		"SELECT lo_import('/etc/passwd')",
		"SELECT pg_sleep(10)",
		"SELECT dblink_connect('host=evil')",
		"SELECT load_extension('x')",
	} {
		if got := ValidateSQL(sql, ValidateOptions{}); got.OK {
			t.Fatalf("ValidateSQL(%q) accepted a dangerous function: %+v", sql, got)
		}
	}
}

// query_to_xml executes SQL supplied as text, which sidesteps the statement
// checks entirely.
func TestValidateSQLRejectsQueryToXMLFamily(t *testing.T) {
	for _, sql := range []string{
		"SELECT query_to_xml('SELECT 1', true, true, '')",
		"SELECT query_to_xmlschema('SELECT 1', true, true, '')",
	} {
		if got := ValidateSQL(sql, ValidateOptions{}); got.OK {
			t.Fatalf("ValidateSQL(%q) accepted text-executed SQL: %+v", sql, got)
		}
	}
}

// The prefixes must stay narrow enough that ordinary catalog reads still work,
// and a literal that merely mentions a blocked name must not trip the check —
// string literals are scrubbed before the scan.
func TestValidateSQLKeepsOrdinaryQueriesUsable(t *testing.T) {
	for _, sql := range []string{
		"SELECT count(*) FROM pg_stat_activity",
		"SELECT rolname FROM pg_roles WHERE rolname = 'pg_read_all_data'",
		"SELECT note FROM audit WHERE note = 'ran pg_ls_dir once'",
		"SELECT id, name FROM users WHERE created_at > '2026-01-01'",
	} {
		if got := ValidateSQL(sql, ValidateOptions{}); !got.OK {
			t.Fatalf("ValidateSQL(%q) rejected an ordinary query: %s", sql, got.Reason)
		}
	}
}
