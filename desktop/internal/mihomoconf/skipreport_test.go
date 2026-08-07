package mihomoconf

import (
	"strings"
	"testing"
)

// The question this exists to answer: a subscription of many links yields fewer
// nodes, and until now nothing recorded which of the two numbers was the truth.
func TestTheReportAccountsForEveryLink(t *testing.T) {
	body := strings.Join([]string{
		"vless://eb3bcbfe-3b07-1a32-3128-a14a2f65c313@one.example.com:443?security=tls&type=ws#one",
		"vless://eb3bcbfe-3b07-1a32-3128-a14a2f65c313@two.example.com:443?security=tls&type=ws#two",
		"ssr://this-is-a-protocol-nobody-here-reads",
		"tuic://also-not-read",
		"tuic://nor-this",
		"vmess://not-valid-base64-so-it-cannot-be-read",
		"# a comment, not a link",
		"",
	}, "\n")

	proxies, _, report, err := ConvertLinksWithReport(body)
	if err != nil {
		t.Fatal(err)
	}

	if report.Links != 6 {
		t.Errorf("six lines looked like links, counted %d", report.Links)
	}
	if report.Converted != len(proxies) || report.Converted != 2 {
		t.Errorf("two links convert, got Converted=%d len=%d", report.Converted, len(proxies))
	}
	// Every link is either converted or accounted for. That is the property
	// worth holding: a link that is neither is one that vanished in silence.
	if report.Skipped() != 4 {
		t.Errorf("four links should be skipped, got %d", report.Skipped())
	}
	if report.Unsupported["ssr"] != 1 || report.Unsupported["tuic"] != 2 {
		t.Errorf("protocols this app does not read are miscounted: %v", report.Unsupported)
	}
	if report.Unreadable["vmess"] != 1 {
		t.Errorf("a vmess link that would not parse should be unreadable, got %v", report.Unreadable)
	}

	// A protocol nobody supports and a link nobody could read are different
	// problems, so the summary keeps them apart.
	summary := report.Summary()
	for _, want := range []string{"6 links", "2 usable", "4 skipped", "2 tuic (not supported)", "1 ssr (not supported)", "1 vmess (unreadable)"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary should mention %q: %s", want, summary)
		}
	}
	// Largest first, so the one worth acting on leads.
	if strings.Index(summary, "2 tuic") > strings.Index(summary, "1 ssr") {
		t.Errorf("the biggest group should come first: %s", summary)
	}
}

// A count that needs no explaining gets none, or this would be in the log on
// every refresh of every healthy subscription.
func TestNothingToExplainSaysNothing(t *testing.T) {
	body := "vless://eb3bcbfe-3b07-1a32-3128-a14a2f65c313@one.example.com:443?security=tls&type=ws#one"
	_, _, report, err := ConvertLinksWithReport(body)
	if err != nil {
		t.Fatal(err)
	}
	if got := report.Summary(); got != "" {
		t.Fatalf("nothing was skipped, so there is nothing to say: %q", got)
	}
}

// The same subscription has to report the same way twice running, or two of
// these cannot be compared.
func TestTheSummaryIsStable(t *testing.T) {
	body := strings.Join([]string{
		"vless://eb3bcbfe-3b07-1a32-3128-a14a2f65c313@one.example.com:443?security=tls&type=ws#one",
		"ssr://a", "tuic://b", "snell://c", "juicity://d",
	}, "\n")

	_, _, first, err := ConvertLinksWithReport(body)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		_, _, again, err := ConvertLinksWithReport(body)
		if err != nil {
			t.Fatal(err)
		}
		if first.Summary() != again.Summary() {
			t.Fatalf("map order leaked into the summary:\n%s\n%s", first.Summary(), again.Summary())
		}
	}
}
