package backend

import (
	"net/http"
	"time"
)

const contentQueueWait = 15 * time.Second

// Preserve the active memory/I/O limits, but let authenticated clients wait
// through a short WAN burst. The bounded shared queue leaves HTTP capacity for
// logins, matchmaking and metadata while large transfers are in progress.
func (s *Server) acquireContentTransfer(r *http.Request, slots chan struct{}) error {
	if r.Context().Err() != nil {
		return fail(408, "Content transfer canceled")
	}
	if s.ctx != nil && s.ctx.Err() != nil {
		return fail(503, "Server is shutting down")
	}
	select {
	case slots <- struct{}{}:
		return nil
	default:
	}
	select {
	case s.contentWaiters <- struct{}{}:
		defer func() { <-s.contentWaiters }()
	default:
		return fail(503, "Content transfer queue is full; retry later")
	}
	var stopped <-chan struct{}
	if s.ctx != nil {
		stopped = s.ctx.Done()
	}
	timer := time.NewTimer(contentQueueWait)
	defer timer.Stop()
	select {
	case <-r.Context().Done():
		return fail(408, "Content transfer canceled")
	case <-stopped:
		return fail(503, "Server is shutting down")
	case <-timer.C:
		return fail(503, "Content transfer queue timed out; retry later")
	case slots <- struct{}{}:
		return nil
	}
}
