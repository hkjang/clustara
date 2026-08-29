package store

import "strings"

// A request log's error field answers "what went wrong", but several surfaces read it as
// "who was at fault" — model quality success rates, the response.completed evaluation. Those
// are judgements about the provider and the model, and they must not be made from something
// the caller did.
const (
	// ClientDisconnectPrefix marks an error the CALLER caused.
	ClientDisconnectPrefix = "client_disconnect"
	// ClientDisconnectError is recorded when the caller closed a stream before it finished.
	// Every "stop generating" button in every chat UI produces one of these, so it is not a
	// rare case: left unlabelled it was recorded as an upstream truncation and counted
	// against the model.
	ClientDisconnectError = ClientDisconnectPrefix + ": caller closed the stream before it finished"
)

// IsCallerAttributedError reports whether a recorded request error describes something the
// caller did rather than something the provider or model did. Per-request views may still
// show these — the request genuinely did not complete — but quality and health judgements
// about the provider must exclude them.
func IsCallerAttributedError(errText string) bool {
	return strings.HasPrefix(errText, ClientDisconnectPrefix)
}
