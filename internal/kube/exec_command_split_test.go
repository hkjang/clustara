package kube

import (
	"reflect"
	"testing"
)

// Pod exec runs argv directly — there is no shell on the far side — so the words
// this splitter produces are literally what runs, and they have to be the words a
// reviewer saw in the approved command string.
func TestSplitCommandLineBuildsShellArgv(t *testing.T) {
	cases := []struct {
		command string
		want    []string
	}{
		{`ls -la /tmp`, []string{"ls", "-la", "/tmp"}},
		{`cat "/var/log/app log.txt"`, []string{"cat", "/var/log/app log.txt"}},
		// An empty quoted word is an argument. Dropping it shifted every later
		// word one position forward, so `sh -c "" ls` executed `sh -c ls`.
		{`sh -c "" ls`, []string{"sh", "-c", "", "ls"}},
		{`sh -c '' ls`, []string{"sh", "-c", "", "ls"}},
		// A backslash is literal inside single quotes and escapes only $ ` " \
		// inside double quotes: `grep 'a\.b'` searched for a.b instead.
		{`grep 'a\.b' /var/log/app.log`, []string{"grep", `a\.b`, "/var/log/app.log"}},
		{`grep "a\.b" /var/log/app.log`, []string{"grep", `a\.b`, "/var/log/app.log"}},
		{`sh -c "echo \"hi\""`, []string{"sh", "-c", `echo "hi"`}},
		{`echo a\ b`, []string{"echo", "a b"}},
		{`echo end\`, []string{"echo", `end\`}},
	}
	for _, tc := range cases {
		got, err := splitCommandLine(tc.command)
		if err != nil {
			t.Errorf("splitCommandLine(%q) returned error: %v", tc.command, err)
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("splitCommandLine(%q) = %q, want %q", tc.command, got, tc.want)
		}
	}
	if _, err := splitCommandLine(`sh -c "rm -rf /`); err == nil {
		t.Error("splitCommandLine accepted an unterminated quote")
	}
}

// A caller that passes argv has already placed each word: podEvidenceCommand runs
// `sh -c <script> <argv0> <path> <query> <n>` and reads the user values as $1..$3.
// Dropping a blank word — or trimming one — hands the script the wrong parameters.
func TestPodExecArgsKeepsCallerArgvPositions(t *testing.T) {
	args := []string{"sh", "-c", "grep -- \"$2\" \"$1\"", "clustara-evidence", "/app", "  padded  ", ""}
	got, err := podExecArgs(PodExecOptions{CommandArg: args})
	if err != nil {
		t.Fatalf("podExecArgs returned error: %v", err)
	}
	if !reflect.DeepEqual(got, args) {
		t.Fatalf("podExecArgs(%q) = %q, want the argv unchanged", args, got)
	}
	if _, err := podExecArgs(PodExecOptions{CommandArg: []string{"  ", "ls"}}); err == nil {
		t.Error("podExecArgs accepted a blank program name")
	}
	if _, err := podExecArgs(PodExecOptions{Command: "   "}); err == nil {
		t.Error("podExecArgs accepted a blank command")
	}
}
