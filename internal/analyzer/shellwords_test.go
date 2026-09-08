package analyzer

import (
	"reflect"
	"testing"
)

// ShellWords must produce the argv the exec API will actually run. Every gate in
// the terminal path classifies the command string, so a word the gates resolve
// differently from the executor is a command reviewed as one thing and run as
// another.
func TestShellWordsResolvesQuotingLikeAShell(t *testing.T) {
	cases := []struct {
		command string
		want    []string
	}{
		{`ls -la /tmp`, []string{"ls", "-la", "/tmp"}},
		{`cat "/var/log/app log.txt"`, []string{"cat", "/var/log/app log.txt"}},
		// An explicitly empty word is an argument: dropping it slides every later
		// word one position forward, so `sh -c "" ls` would run `sh -c ls`.
		{`sh -c "" ls`, []string{"sh", "-c", "", "ls"}},
		{`sh -c '' ls`, []string{"sh", "-c", "", "ls"}},
		// Quotes and escapes inside a word are resolved, so the program name is
		// the one that will run.
		{`r"m" -rf /`, []string{"rm", "-rf", "/"}},
		{`\rm -rf /`, []string{"rm", "-rf", "/"}},
		{`re"boot"`, []string{"reboot"}},
		{`shut'down' -h now`, []string{"shutdown", "-h", "now"}},
		// A backslash is literal inside single quotes and escapes only $ ` " \
		// inside double quotes.
		{`grep 'a\.b' app.log`, []string{"grep", `a\.b`, "app.log"}},
		{`grep "a\.b" app.log`, []string{"grep", `a\.b`, "app.log"}},
		{`echo "say \"hi\""`, []string{"echo", `say "hi"`}},
		{`echo a\ b`, []string{"echo", "a b"}},
		{`echo end\`, []string{"echo", `end\`}},
		{``, []string{}},
	}
	for _, tc := range cases {
		got, err := ShellWords(tc.command)
		if err != nil {
			t.Errorf("ShellWords(%q) returned error: %v", tc.command, err)
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("ShellWords(%q) = %q, want %q", tc.command, got, tc.want)
		}
	}
}

// An unterminated quote is reported, but the words parsed so far still come back:
// the gates classify what they can rather than seeing an empty command.
func TestShellWordsReportsUnterminatedQuoteAndKeepsWords(t *testing.T) {
	got, err := ShellWords(`sh -c "rm -rf /`)
	if err == nil {
		t.Fatalf("ShellWords with an unterminated quote returned no error (got %q)", got)
	}
	if len(got) == 0 || got[0] != "sh" {
		t.Fatalf("ShellWords kept no words for an unterminated quote: %q", got)
	}
}
