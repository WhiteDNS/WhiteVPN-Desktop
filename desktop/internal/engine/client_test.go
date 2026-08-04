package engine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// fakeCore is the other end of a connection, standing in for the real core.
type fakeCore struct {
	conn    net.Conn
	t       *testing.T
	handler func(action) (result, bool)
}

func newFakeCore(t *testing.T, handler func(action) (result, bool)) (*Client, *fakeCore) {
	t.Helper()
	ours, theirs := net.Pipe()
	core := &fakeCore{conn: theirs, t: t, handler: handler}
	go core.serve()
	client := NewClient(ours, 8)
	t.Cleanup(func() { _ = client.Close() })
	return client, core
}

func (f *fakeCore) serve() {
	for {
		payload, err := readFrame(f.conn)
		if err != nil {
			return
		}
		var incoming action
		if json.Unmarshal(payload, &incoming) != nil {
			continue
		}
		reply, answer := f.handler(incoming)
		if !answer {
			// Deliberately silent, which is what the real core does with a method
			// it does not implement.
			continue
		}
		reply.ID = incoming.ID
		reply.Method = incoming.Method
		out, _ := json.Marshal(reply)
		if writeFrame(f.conn, out) != nil {
			return
		}
	}
}

func ok(data string) result { return result{Code: 0, Data: json.RawMessage(data)} }

func TestInvokeReturnsTheReplyForItsOwnRequest(t *testing.T) {
	client, _ := newFakeCore(t, func(a action) (result, bool) {
		return ok(`"pong"`), true
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	raw, err := client.invoke(ctx, "ping", nil)
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if decodeString(raw) != "pong" {
		t.Fatalf("unexpected reply: %s", raw)
	}
}

// The core drops methods it does not know without replying. A caller that waits
// for ever is the failure this guards against.
func TestInvokeGivesUpWhenTheCoreNeverReplies(t *testing.T) {
	client, _ := newFakeCore(t, func(a action) (result, bool) {
		return result{}, false
	})

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := client.invoke(ctx, "definitelyNotAMethod", nil)
	if !errors.Is(err, ErrNoReply) {
		t.Fatalf("expected ErrNoReply, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("took %s to give up", elapsed)
	}
}

func TestInvokeReportsANonZeroCodeAsFailure(t *testing.T) {
	client, _ := newFakeCore(t, func(a action) (result, bool) {
		return result{Code: -1, Data: json.RawMessage(`"internal panic"`)}, true
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := client.invoke(ctx, "initClash", "{}")

	var failure Failure
	if !errors.As(err, &failure) {
		t.Fatalf("expected a Failure, got %v", err)
	}
	if failure.Code != -1 || failure.Method != "initClash" {
		t.Fatalf("unexpected failure: %#v", failure)
	}
}

// Replies are matched by id, so a reply that arrives late or out of order must
// reach the call that asked for it and no other.
func TestConcurrentCallsEachGetTheirOwnReply(t *testing.T) {
	client, _ := newFakeCore(t, func(a action) (result, bool) {
		return ok(`"` + a.Method + `"`), true
	})

	methods := []string{"getProxies", "getTraffic", "getConnections", "getMemory"}
	type outcome struct {
		method string
		got    string
		err    error
	}
	results := make(chan outcome, len(methods))
	for _, method := range methods {
		go func(method string) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			raw, err := client.invoke(ctx, method, nil)
			results <- outcome{method, decodeString(raw), err}
		}(method)
	}
	for range methods {
		r := <-results
		if r.err != nil {
			t.Fatalf("%s: %v", r.method, r.err)
		}
		if r.got != r.method {
			t.Fatalf("%s received %q, which belongs to another call", r.method, r.got)
		}
	}
}

// A dead core must fail outstanding calls rather than leave them to time out one
// by one against a connection already known to be gone.
func TestOutstandingCallsFailWhenTheConnectionDies(t *testing.T) {
	ours, theirs := net.Pipe()
	client := NewClient(ours, 4)

	failed := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := client.invoke(ctx, "getProxies", nil)
		failed <- err
	}()

	time.Sleep(50 * time.Millisecond)
	_ = theirs.Close()

	select {
	case err := <-failed:
		if err == nil {
			t.Fatal("expected the call to fail once the connection died")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("call was left hanging after the connection died")
	}
}

func TestCallsAfterCloseFailImmediately(t *testing.T) {
	client, _ := newFakeCore(t, func(a action) (result, bool) { return ok(`""`), true })
	_ = client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := client.invoke(ctx, "getProxies", nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
}

// Frames with no call waiting for them are events, not stray replies.
func TestUnmatchedFramesBecomeEvents(t *testing.T) {
	ours, theirs := net.Pipe()
	client := NewClient(ours, 4)
	t.Cleanup(func() { _ = client.Close() })

	go func() {
		out, _ := json.Marshal(result{ID: "nobody-is-waiting", Method: "message", Data: json.RawMessage(`"a log line"`)})
		_ = writeFrame(theirs, out)
	}()

	select {
	case event := <-client.Events():
		if event.Method != "message" {
			t.Fatalf("unexpected event: %#v", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("event never arrived")
	}
}

// A consumer that stops draining events must not be able to wedge the reader and
// take every pending call down with it.
func TestEventsAreDroppedRatherThanBlockingTheReader(t *testing.T) {
	ours, theirs := net.Pipe()
	client := NewClient(ours, 1)
	t.Cleanup(func() { _ = client.Close() })

	go func() {
		for i := 0; i < 20; i++ {
			out, _ := json.Marshal(result{ID: "unmatched", Method: "message", Data: json.RawMessage(`"x"`)})
			if writeFrame(theirs, out) != nil {
				return
			}
		}
		// Nobody drains Events, so the reader must still be alive to answer this.
		var incoming action
		payload, err := readFrame(theirs)
		if err != nil {
			return
		}
		_ = json.Unmarshal(payload, &incoming)
		reply, _ := json.Marshal(result{ID: incoming.ID, Method: incoming.Method, Data: json.RawMessage(`"alive"`)})
		_ = writeFrame(theirs, reply)
	}()

	time.Sleep(100 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	raw, err := client.invoke(ctx, "getProxies", nil)
	if err != nil {
		t.Fatalf("reader stopped serving calls while events went undrained: %v", err)
	}
	if decodeString(raw) != "alive" {
		t.Fatalf("unexpected reply %s", raw)
	}
	if client.DroppedEvents() == 0 {
		t.Fatal("expected some events to have been dropped and counted")
	}
}

func TestFrameRoundTripsAndRefusesAnAbsurdLength(t *testing.T) {
	pipeR, pipeW := net.Pipe()
	go func() {
		_ = writeFrame(pipeW, []byte(`{"id":"a"}`))
		// A length prefix larger than the cap: allocating on it unchecked turns a
		// bad frame into an out-of-memory kill.
		_, _ = pipeW.Write([]byte{0xff, 0xff, 0xff, 0xff})
		_ = pipeW.Close()
	}()

	payload, err := readFrame(pipeR)
	if err != nil || string(payload) != `{"id":"a"}` {
		t.Fatalf("round trip failed: %q %v", payload, err)
	}
	if _, err := readFrame(pipeR); err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("expected an explicit size error, got %v", err)
	}
}
