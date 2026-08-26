package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// SaveOIDCFlowState persists a short-lived OIDC login-flow state (state → nonce + PKCE verifier)
// so the Authorization Code callback can validate it even if it lands on a different instance or
// after a restart. Opportunistically prunes entries older than 10 minutes.
func (s *SQLStore) SaveOIDCFlowState(ctx context.Context, state, nonce, verifier string, createdAt time.Time) error {
	cutoff := createdAt.Add(-10 * time.Minute).UTC().Format(time.RFC3339Nano)
	_, _ = s.db.ExecContext(ctx, s.bind(`DELETE FROM oidc_flow_states WHERE created_at < ?`), cutoff)
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO oidc_flow_states (state, nonce, verifier, created_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(state) DO UPDATE SET nonce=excluded.nonce, verifier=excluded.verifier, created_at=excluded.created_at`),
		state, nonce, verifier, createdAt.UTC().Format(time.RFC3339Nano))
	return err
}

// TakeOIDCFlowState atomically consumes a flow state: it returns the nonce/verifier and deletes
// the row. found is false if the state is unknown or older than the 10-minute TTL.
func (s *SQLStore) TakeOIDCFlowState(ctx context.Context, state string) (nonce, verifier string, found bool, err error) {
	var createdAt string
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT nonce, verifier, created_at FROM oidc_flow_states WHERE state = ?`), state)
	if err = row.Scan(&nonce, &verifier, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", false, nil
		}
		return "", "", false, err
	}
	// Consume regardless of age (single-use). The DELETE is the guard, not the SELECT:
	// exactly one caller can affect the row, so only that caller may treat the state as
	// consumed. Reading first and deleting unconditionally let two simultaneous
	// callbacks both come back found=true — the opposite of the single-use property
	// this function documents. A failed delete means single use cannot be guaranteed,
	// so it is reported rather than swallowed.
	res, derr := s.db.ExecContext(ctx, s.bind(`DELETE FROM oidc_flow_states WHERE state = ?`), state)
	if derr != nil {
		return "", "", false, derr
	}
	if affected, aerr := res.RowsAffected(); aerr != nil {
		return "", "", false, aerr
	} else if affected != 1 {
		return "", "", false, nil
	}
	if ts, perr := time.Parse(time.RFC3339Nano, createdAt); perr == nil && time.Since(ts) > 10*time.Minute {
		return "", "", false, nil
	}
	return nonce, verifier, true, nil
}
