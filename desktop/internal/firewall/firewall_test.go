package firewall

import "testing"

func TestParseMacOSFirewallStatus(t *testing.T) {
	testCases := []struct {
		name        string
		output      string
		wantEnabled bool
		wantOK      bool
	}{
		{name: "enabled state", output: "Firewall is enabled. (State = 1)", wantEnabled: true, wantOK: true},
		{name: "disabled state", output: "Firewall is disabled. (State = 0)", wantEnabled: false, wantOK: true},
		{name: "unknown", output: "unexpected", wantEnabled: false, wantOK: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			enabled, ok := parseMacOSFirewallStatus(testCase.output)
			if enabled != testCase.wantEnabled || ok != testCase.wantOK {
				t.Fatalf("expected enabled=%t ok=%t, got enabled=%t ok=%t", testCase.wantEnabled, testCase.wantOK, enabled, ok)
			}
		})
	}
}

func TestParseWindowsFirewallStatus(t *testing.T) {
	testCases := []struct {
		name        string
		output      string
		wantEnabled bool
		wantOK      bool
	}{
		{
			name:        "one profile on",
			output:      "Domain Profile Settings:\nState                                 OFF\nPrivate Profile Settings:\nState                                 ON\n",
			wantEnabled: true,
			wantOK:      true,
		},
		{
			name:        "all profiles off",
			output:      "Domain Profile Settings:\nState OFF\nPrivate Profile Settings:\nState OFF\nPublic Profile Settings:\nState OFF\n",
			wantEnabled: false,
			wantOK:      true,
		},
		{name: "unknown", output: "No state lines here", wantEnabled: false, wantOK: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			enabled, ok := parseWindowsFirewallStatus(testCase.output)
			if enabled != testCase.wantEnabled || ok != testCase.wantOK {
				t.Fatalf("expected enabled=%t ok=%t, got enabled=%t ok=%t", testCase.wantEnabled, testCase.wantOK, enabled, ok)
			}
		})
	}
}

func TestParseLinuxFirewallStatuses(t *testing.T) {
	testCases := []struct {
		name        string
		parser      func(string) (bool, bool)
		output      string
		wantEnabled bool
		wantOK      bool
	}{
		{name: "ufw active", parser: parseUFWStatus, output: "Status: active\n", wantEnabled: true, wantOK: true},
		{name: "ufw inactive", parser: parseUFWStatus, output: "Status: inactive\n", wantEnabled: false, wantOK: true},
		{name: "ufw unknown", parser: parseUFWStatus, output: "ERROR: problem running iptables", wantEnabled: false, wantOK: false},
		{name: "firewalld running", parser: parseFirewalldStatus, output: "running\n", wantEnabled: true, wantOK: true},
		{name: "firewalld stopped", parser: parseFirewalldStatus, output: "not running\n", wantEnabled: false, wantOK: true},
		{name: "firewalld unknown", parser: parseFirewalldStatus, output: "failed\n", wantEnabled: false, wantOK: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			enabled, ok := testCase.parser(testCase.output)
			if enabled != testCase.wantEnabled || ok != testCase.wantOK {
				t.Fatalf("expected enabled=%t ok=%t, got enabled=%t ok=%t", testCase.wantEnabled, testCase.wantOK, enabled, ok)
			}
		})
	}
}
