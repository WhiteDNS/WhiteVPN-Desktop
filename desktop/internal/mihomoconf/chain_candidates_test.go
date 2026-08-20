package mihomoconf

import "testing"

// What comes back is what the first hop may be, and a caller selecting a proxy
// has to select from it. Naming the exit's own node, or a TCP node under a
// datagram exit, would name one the group does not contain — and the failure
// would arrive at connect time as the engine refusing a selection nobody could
// see was invalid.
func TestTheCandidatesReturnedAreWhatTheGroupActuallyHolds(t *testing.T) {
	document, candidates, err := BuildProxiesYAMLWithChain(chainProxies(), SplitTunnel{}, Chain{ExitNode: "TCP Two"})
	if err != nil {
		t.Fatal(err)
	}
	_ = document

	for _, name := range candidates {
		if name == "TCP Two" {
			t.Fatal("the exit's own node is not a first hop")
		}
	}
	if len(candidates) != 3 {
		t.Fatalf("expected the other three nodes, got %v", candidates)
	}
}

// The datagram case: candidates and group membership have to agree, or the
// session selects something the engine has never heard of.
func TestTheCandidatesNarrowWithTheGroupForAUDPExit(t *testing.T) {
	_, candidates, err := BuildProxiesYAMLWithChain(chainProxies(), SplitTunnel{}, Chain{ExitNode: "Wire One"})
	if err != nil {
		t.Fatal(err)
	}
	// Only the Hysteria2 node can carry UDP for it.
	if len(candidates) != 1 || candidates[0] != "UDP One" {
		t.Fatalf("expected only the UDP-capable node, got %v", candidates)
	}
}

// Without a chain the candidates are simply everything, as they always were.
func TestWithoutAChainEveryNodeIsACandidate(t *testing.T) {
	_, candidates, err := BuildProxiesYAMLWithChain(chainProxies(), SplitTunnel{}, Chain{})
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 4 {
		t.Fatalf("expected every node, got %v", candidates)
	}
}
