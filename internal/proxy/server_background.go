package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"time"
)

// startBackground runs one NewServer-owned scheduler on a goroutine whose
// context Shutdown cancels. Panics are contained so a single bad tick cannot
// take the process down, and the goroutine is registered with the wait group
// Shutdown drains.
func (s *Server) startBackground(name string, run func(context.Context)) {
	if s == nil || run == nil || s.baseCtx == nil {
		return
	}
	s.background.Add(1)
	go func() {
		defer s.background.Done()
		defer func() {
			if recovered := recover(); recovered != nil {
				slog.Error("background scheduler panicked", "scheduler", name,
					"panic", fmt.Sprint(recovered), "stack", string(debug.Stack()))
			}
		}()
		run(s.baseCtx)
	}()
}

// Shutdown stops the schedulers NewServer started and waits for them to return.
// Callers must invoke it before closing the store: these are polling loops with
// no other stop signal, so without it they keep issuing queries against a closed
// database for the rest of the process lifetime.
//
// In-flight ticks are cancelled rather than drained. Every scheduler here is an
// idempotent poller that resumes from persisted state on the next start, so
// waiting out a long-running snapshot would delay shutdown for no benefit.
func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.shutdownOnce.Do(func() {
		if s.stopBase != nil {
			s.stopBase()
		}
	})
	done := make(chan struct{})
	go func() {
		s.background.Wait()
		close(done)
	}()
	if ctx == nil {
		<-done
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("background schedulers did not stop: %w", ctx.Err())
	}
}

// schedulerTickContext derives one tick's context from the server lifecycle so a
// shutdown interrupts the tick instead of letting it run against a closed store.
func schedulerTickContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, timeout)
}

// waitForSchedulerTick blocks until the next tick is due, reporting false when
// the server is shutting down.
func waitForSchedulerTick(ctx context.Context, tick <-chan time.Time) bool {
	select {
	case <-ctx.Done():
		return false
	case <-tick:
		return ctx.Err() == nil
	}
}
