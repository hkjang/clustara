package proxy

import (
	"encoding/json"
	"io"
	"net/http"
)

// maxPartialUpdateBody bounds a request body read for presence detection. These
// are small admin records; the cap exists so a malformed client cannot make the
// second parse expensive.
const maxPartialUpdateBody = 1 << 20

// decodeWithPresence decodes a request body into v and reports which top-level
// JSON keys it actually carried.
//
// Handlers that upsert a decoded record wholesale turn every absent key into its
// Go zero value, so a request meaning to change one field silently rewrites the
// rest. That is worst for bool: omitting "enabled" from a policy or a service
// catalog update decodes as false and switches the thing off — and for the
// service catalog, disabling is exactly what DELETE does, so an omitted key
// performs the delete.
//
// Knowing which keys were present is what lets a handler distinguish "set this
// to false" from "did not mention it". Callers keep their stored value for
// anything not named here.
func decodeWithPresence(r *http.Request, v any) (map[string]bool, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxPartialUpdateBody))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, v); err != nil {
		return nil, err
	}
	raw := map[string]json.RawMessage{}
	// A body that decoded into v but is not an object (an array, say) has no keys
	// to report; the caller then keeps every stored value, which is the safe read.
	_ = json.Unmarshal(body, &raw)
	present := make(map[string]bool, len(raw))
	for key := range raw {
		present[key] = true
	}
	return present, nil
}
