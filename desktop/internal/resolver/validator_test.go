package resolver

import "testing"

func TestValidateTextNormalizesAndDeduplicatesResolvers(t *testing.T) {
	result := ValidateText(`
		# comment
		1.1.1.1
		"1.1.1.1:53"; 8.8.8.8:5353
		[2606:4700:4700::1111]:53
		192.0.2.0/30
	`)

	if !result.IsValid {
		t.Fatalf("expected valid resolver text, invalid=%v", result.InvalidEntries)
	}
	want := "1.1.1.1\n8.8.8.8:5353\n2606:4700:4700::1111\n192.0.2.0/30"
	if result.NormalizedText != want {
		t.Fatalf("normalized text mismatch\nwant:\n%s\ngot:\n%s", want, result.NormalizedText)
	}
}

func TestValidateTextReportsInvalidEntries(t *testing.T) {
	result := ValidateText("1.1.1.1\nbad-host\n999.1.1.1")
	if result.IsValid {
		t.Fatal("expected validation failure")
	}
	if len(result.InvalidEntries) != 2 {
		t.Fatalf("expected 2 invalid entries, got %v", result.InvalidEntries)
	}
}
