package engine

import "testing"

func TestPipeSecurityDescriptorIncludesTheAppUser(t *testing.T) {
	const sid = "S-1-5-21-1000"
	want := "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;S-1-5-21-1000)"
	if got := pipeSecurityDescriptor(sid); got != want {
		t.Fatalf("unexpected pipe security descriptor: %q", got)
	}
}
