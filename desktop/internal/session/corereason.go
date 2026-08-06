package session

import (
	"io"
	"strings"
	"sync"
)

// Why a connection failed, according to the engine.
//
// The engine knows. It writes lines like
//
//	[TCP] dial ... --> cloudflare.com:443 error: example.com:443 connect error: REALITY authentication failed
//
// and the app was reporting "no request completed through the proxy within
// 12s" — true, and useless. One of those tells someone their REALITY keys no
// longer match the server; the other tells them to try again. Working out which
// it was meant opening the Logs page and knowing what to look for, and the
// people hitting this are the ones least likely to do either.
//
// So the engine's own output is read on the way past, and the last reason it
// gave is attached to the failure.

// The reason is taken from after these, longest match first, so the innermost
// explanation wins over the wrapper around it.
var coreReasonMarkers = []string{"connect error: ", "error: "}

// coreReasonLimit keeps a runaway line out of a dialog. Engine reasons are a
// short phrase; anything longer is not one.
const coreReasonLimit = 160

// coreReasonTap remembers the last failure reason the engine gave.
//
// It watches both streams rather than only stderr. The engine writes its log to
// stdout — dial failures included — so tapping stderr alone recorded nothing at
// all, which is how this was written the first time and why it had to be
// tested against a config that really does fail rather than only in a unit test.
type coreReasonTap struct {
	mu     sync.Mutex
	reason string
}

func newCoreReasonTap() *coreReasonTap {
	return &coreReasonTap{}
}

// Watch returns a writer that passes everything to inner untouched while
// reading it on the way past. inner may be nil.
func (t *coreReasonTap) Watch(inner io.Writer) io.Writer {
	return &coreReasonStream{tap: t, inner: inner}
}

func (t *coreReasonTap) record(reason string) {
	t.mu.Lock()
	t.reason = reason
	t.mu.Unlock()
}

type coreReasonStream struct {
	tap   *coreReasonTap
	inner io.Writer
}

func (s *coreReasonStream) Write(p []byte) (int, error) {
	if reason := coreFailureReason(string(p)); reason != "" {
		s.tap.record(reason)
	}
	if s.inner == nil {
		return len(p), nil
	}
	return s.inner.Write(p)
}

// Reason is the last failure the engine reported, or empty if it reported none.
func (t *coreReasonTap) Reason() string {
	if t == nil {
		return ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.reason
}

// coreFailureReason pulls the explanation out of an engine log line.
//
// Only the reason itself is taken, never the whole line: the line names the
// server being dialled, and a failure that quotes it puts a user's own host into
// a dialog they may well screenshot.
func coreFailureReason(chunk string) string {
	best := ""
	for _, line := range strings.Split(chunk, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		for _, marker := range coreReasonMarkers {
			index := strings.LastIndex(line, marker)
			if index < 0 {
				continue
			}
			reason := strings.TrimSpace(line[index+len(marker):])
			// The engine's lines are `msg="..."`, so a reason at the end of one
			// carries the closing quote.
			reason = strings.TrimRight(reason, `"`)
			if reason == "" || len(reason) > coreReasonLimit {
				continue
			}
			best = reason
			break
		}
	}
	return best
}
