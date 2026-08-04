// Package engine speaks to the mihomo core that WhiteVPN for Android runs.
//
// On Android the core is a c-shared library loaded in-process, and the app calls
// into it through JNI. Off Android there is no cgo build: the same source
// compiles to an executable whose entry point takes a pipe or socket path as its
// only argument, dials back to it, and then exchanges length-prefixed JSON
// frames. That is the transport implemented here.
//
// Two properties of the core shape this package, and both were measured rather
// than assumed:
//
//   - The `data` field of an action is not a nested object. The core does a Go
//     type assertion on it per method — a JSON string for most, a bool for the
//     traffic calls — and an object where a string is expected panics the
//     handler. Callers do not construct actions directly for this reason; the
//     wrappers in actions.go encode each one the way its handler expects.
//
//   - An unknown method produces no reply at all. The core's dispatcher falls
//     through to a handler that returns false without writing anything back, so
//     a caller that waits without a deadline waits for ever. Every call in this
//     package therefore takes a context and treats its expiry as an error.
package engine

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// maxFrameSize bounds a single frame. The length prefix is attacker-controlled
// in the sense that a confused or hostile core could send a huge one, and
// allocating on it unchecked turns a bad frame into an out-of-memory kill.
const maxFrameSize = 64 << 20

// action is one request. Data is `any` because its JSON type varies per method.
type action struct {
	ID     string `json:"id"`
	Method string `json:"method"`
	Data   any    `json:"data,omitempty"`
}

// result is one reply. Code is zero on success; anything else means the core
// refused, and Data then carries its explanation.
type result struct {
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Code   int             `json:"code"`
	Data   json.RawMessage `json:"data"`
}

func writeFrame(w io.Writer, payload []byte) error {
	frame := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint32(frame, uint32(len(payload)))
	copy(frame[4:], payload)
	_, err := w.Write(frame)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	size := binary.LittleEndian.Uint32(header[:])
	if size > maxFrameSize {
		return nil, fmt.Errorf("engine: frame of %d bytes exceeds the %d byte limit", size, maxFrameSize)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
