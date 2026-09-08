package analyzer

import (
	"fmt"
	"strings"
)

// ShellWords splits a command line into the words a shell would hand to execve:
// quotes are removed, backslash escapes are resolved, and an explicitly empty
// word ("" or '') survives as an empty argument.
//
// This exists because one command string is read by two different parsers — the
// gates (Command Risk Parser, terminal deny matcher, access-mode classifier) and
// the executor that builds argv for the Kubernetes exec API. The gates used to
// look at the raw bytes and strip only *surrounding* quotes, so a program name
// spelled `r"m"`, `re"boot"` or `\rm` read as an unknown program to them while
// the executor resolved it back to the real one and ran it.
//
// Quoting rules follow POSIX: inside '' every byte is literal (a backslash
// included); inside "" a backslash escapes only $ ` " and \; outside quotes a
// backslash escapes the next character. A trailing lone backslash is kept as a
// literal backslash rather than dropped.
//
// An unterminated quote returns an error together with the words parsed so far,
// so callers that must not guess (the executor) can refuse while callers that
// only classify (the gates) still see something to classify.
func ShellWords(command string) ([]string, error) {
	runes := []rune(command)
	out := []string{}
	var b strings.Builder
	var quote rune
	word := false
	flush := func() {
		if word {
			out = append(out, b.String())
			b.Reset()
			word = false
		}
	}
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch {
		case quote == '\'':
			if r == '\'' {
				quote = 0
			} else {
				b.WriteRune(r)
			}
		case quote == '"':
			if r == '"' {
				quote = 0
				continue
			}
			if r == '\\' && i+1 < len(runes) && strings.ContainsRune("$`\"\\", runes[i+1]) {
				i++
				b.WriteRune(runes[i])
				continue
			}
			b.WriteRune(r)
		case r == '\\':
			if i+1 < len(runes) {
				i++
				b.WriteRune(runes[i])
			} else {
				b.WriteRune(r)
			}
			word = true
		case r == '\'' || r == '"':
			quote = r
			word = true
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			flush()
		default:
			b.WriteRune(r)
			word = true
		}
	}
	flush()
	if quote != 0 {
		return out, fmt.Errorf("unterminated quote in command")
	}
	return out, nil
}

// shellDequote resolves the quoting of a single already-split token, so a token
// is compared by what it will actually execute as. Tokens carry no whitespace,
// so the resolved words are simply concatenated (`a"b"c` is one word `abc`).
func shellDequote(token string) string {
	words, _ := ShellWords(token)
	if len(words) == 0 {
		return ""
	}
	if len(words) == 1 {
		return words[0]
	}
	return strings.Join(words, "")
}
