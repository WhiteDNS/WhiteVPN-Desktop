package engine

import (
	"encoding/json"
	"testing"
)

// The reply is a JSON string holding JSON, like most of this protocol's. Getting
// that unwrapping wrong is silent: the numbers just stay at zero.
func TestDecodeTrafficUnwrapsBothLayers(t *testing.T) {
	inner, err := json.Marshal(map[string]int64{"up": 1234, "down": 5678})
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := json.Marshal(string(inner))
	if err != nil {
		t.Fatal(err)
	}

	up, down, err := decodeTraffic(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if up != 1234 || down != 5678 {
		t.Fatalf("up=%d down=%d, want 1234/5678", up, down)
	}

	// A core that answers with nothing is not a core reporting no traffic.
	if _, _, err := decodeTraffic(json.RawMessage(`""`)); err == nil {
		t.Fatal("expected an empty reply to be an error, not zero traffic")
	}
}
