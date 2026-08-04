package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

var (
	// ErrClosed means the connection to the core is gone. Calls fail with this
	// rather than blocking, so a dead core surfaces as an error instead of a hang.
	ErrClosed = errors.New("engine: connection is closed")
	// ErrNoReply means the deadline passed with nothing back. The most likely
	// cause is a method this core does not implement: its dispatcher drops those
	// silently, so silence and "unknown method" are indistinguishable from here.
	ErrNoReply = errors.New("engine: no reply before the deadline")
)

// Failure is a reply the core answered with a non-zero code.
type Failure struct {
	Method string
	Code   int
	Detail string
}

func (f Failure) Error() string {
	return fmt.Sprintf("engine %s: code %d: %s", f.Method, f.Code, f.Detail)
}

// Event is an unsolicited frame: logs, traffic samples and similar. They arrive
// with no request outstanding, so they cannot be returned to a caller.
type Event struct {
	Method string
	Data   json.RawMessage
}

// Client drives one core over one connection. Safe for concurrent use.
type Client struct {
	conn io.ReadWriteCloser

	mu      sync.Mutex
	pending map[string]chan result
	closed  bool

	sequence atomic.Uint64
	events   chan Event
	dropped  atomic.Int64

	done      chan struct{}
	closeOnce sync.Once
	readErr   atomic.Value
}

// NewClient starts reading from conn. eventBuffer bounds the event channel; when
// it is full events are counted and discarded rather than blocking the reader,
// because a consumer that stops draining must not be able to wedge the transport
// and take every pending call down with it.
func NewClient(conn io.ReadWriteCloser, eventBuffer int) *Client {
	if eventBuffer <= 0 {
		eventBuffer = 64
	}
	c := &Client{
		conn:    conn,
		pending: make(map[string]chan result),
		events:  make(chan Event, eventBuffer),
		done:    make(chan struct{}),
	}
	go c.readLoop()
	return c
}

// Events yields unsolicited frames. It is closed when the connection ends.
func (c *Client) Events() <-chan Event { return c.events }

// DroppedEvents counts events discarded because the buffer was full.
func (c *Client) DroppedEvents() int64 { return c.dropped.Load() }

// Done is closed when the connection ends, for whatever reason.
func (c *Client) Done() <-chan struct{} { return c.done }

// Err reports why the connection ended, or nil if it ended cleanly.
func (c *Client) Err() error {
	if err, ok := c.readErr.Load().(error); ok {
		return err
	}
	return nil
}

func (c *Client) readLoop() {
	defer c.finish()
	for {
		payload, err := readFrame(c.conn)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				c.readErr.Store(err)
			}
			return
		}
		var reply result
		if err := json.Unmarshal(payload, &reply); err != nil {
			// A frame we cannot parse is not worth tearing the connection down
			// for: the next one is usually fine, and dropping the link would fail
			// every outstanding call for one bad message.
			continue
		}

		c.mu.Lock()
		waiter, waiting := c.pending[reply.ID]
		if waiting {
			delete(c.pending, reply.ID)
		}
		c.mu.Unlock()

		if waiting {
			waiter <- reply
			continue
		}
		select {
		case c.events <- Event{Method: reply.Method, Data: reply.Data}:
		default:
			c.dropped.Add(1)
		}
	}
}

// finish fails every outstanding call. Without this they would each wait out
// their own deadline against a connection already known to be gone.
func (c *Client) finish() {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		waiters := c.pending
		c.pending = map[string]chan result{}
		c.mu.Unlock()

		for id, waiter := range waiters {
			waiter <- result{ID: id, Code: -1, Data: json.RawMessage(`"connection closed"`)}
		}
		close(c.events)
		close(c.done)
	})
}

// invoke sends one action and waits for its reply.
//
// data must already be in the shape the method's handler asserts — see the note
// in protocol.go. Callers should prefer the wrappers in actions.go.
func (c *Client) invoke(ctx context.Context, method string, data any) (json.RawMessage, error) {
	id := fmt.Sprintf("%s-%d", method, c.sequence.Add(1))
	waiter := make(chan result, 1)

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrClosed
	}
	c.pending[id] = waiter
	c.mu.Unlock()

	payload, err := json.Marshal(action{ID: id, Method: method, Data: data})
	if err != nil {
		c.forget(id)
		return nil, err
	}
	if err := writeFrame(c.conn, payload); err != nil {
		c.forget(id)
		return nil, fmt.Errorf("engine: write %s: %w", method, err)
	}

	select {
	case reply := <-waiter:
		if reply.Code != 0 {
			return reply.Data, Failure{Method: method, Code: reply.Code, Detail: string(reply.Data)}
		}
		return reply.Data, nil
	case <-ctx.Done():
		c.forget(id)
		return nil, fmt.Errorf("%w: %s", ErrNoReply, method)
	}
}

func (c *Client) forget(id string) {
	c.mu.Lock()
	delete(c.pending, id)
	c.mu.Unlock()
}

// Close ends the connection. Outstanding calls fail rather than hang.
func (c *Client) Close() error {
	err := c.conn.Close()
	<-c.done
	return err
}
