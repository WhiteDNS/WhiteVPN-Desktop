package mihomoconf

import (
	"strings"
	"testing"
)

// The commonest reasons a subscription will not load are not "it has no V2Ray
// links": they are a login page, an error page and an empty response. Each has
// to be recognisable from the message alone, because that message is all a user
// can send back.
func TestFailureSaysWhatArrived(t *testing.T) {
	for _, testCase := range []struct{ body, want string }{
		{"", "returned nothing"},
		{"   \n ", "returned nothing"},
		{"<!DOCTYPE html><html><body>Sign in</body></html>", "web page"},
		{`{"hello": "world"}`, "JSON"},
		{"ftp://example.com/file", "links"},
		{"just some words", "neither share links"},
	} {
		_, _, err := ParseSubscription(testCase.body)
		if err == nil {
			t.Fatalf("%q should have been refused", testCase.body)
		}
		if !strings.Contains(err.Error(), testCase.want) {
			t.Fatalf("%q: expected the message to mention %q, got %v", testCase.body, testCase.want, err)
		}
	}
}

// The body carries credentials and the message ends up in screenshots.
func TestFailureNeverRepeatsTheBody(t *testing.T) {
	secret := "vmess://c3VwZXItc2VjcmV0LWNyZWRlbnRpYWw"
	_, _, err := ParseSubscription("<html>" + secret + "</html>")
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("the message repeated the body: %v", err)
	}
}
