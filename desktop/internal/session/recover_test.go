package session

import (
	"context"
	"reflect"
	"testing"
)

// A session with nothing running, or a subscription that chose its own node,
// has nowhere to move to. Saying so beats silently doing nothing.
func TestRecoverRefusesWhenThereIsNowhereToGo(t *testing.T) {
	if _, err := (&Session{}).Recover(context.Background(), 3); err == nil {
		t.Fatal("expected recovery to be refused when nothing is running")
	}
}

// The node that just failed is not a candidate for replacing itself, and one
// recovery does not work through a 995-node catalogue.
func TestRecoveryOrderSkipsTheFailedNodeAndStops(t *testing.T) {
	got := recoveryOrder([]string{"a", "b", "c", "d"}, "b", 2)
	if want := []string{"a", "c"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("recoveryOrder = %#v, want %#v", got, want)
	}
	if got := recoveryOrder([]string{"only"}, "only", 5); len(got) != 0 {
		t.Fatalf("with one node and that node failing there is nothing to try, got %#v", got)
	}
	if got := recoveryOrder([]string{"a", "b"}, "", 5); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("with nothing selected every node is a candidate, got %#v", got)
	}
}
