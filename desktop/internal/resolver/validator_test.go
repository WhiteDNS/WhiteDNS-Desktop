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

func TestValidateTextSupportsIPv6OnlyAndMixedResolverLists(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "ipv6 only",
			raw:  "2001:4860:4860::8888\n[2606:4700:4700::1111]:5353\n[fe80::1%eth0]:5353",
			want: "2001:4860:4860::8888\n[2606:4700:4700::1111]:5353\n[fe80::1%eth0]:5353",
		},
		{
			name: "mixed families",
			raw:  "1.1.1.1; [2001:4860:4860::8844]:53; 192.0.2.0/30; 2001:db8::/126",
			want: "1.1.1.1\n2001:4860:4860::8844\n192.0.2.0/30\n2001:db8::/126",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := ValidateText(test.raw)
			if !result.IsValid {
				t.Fatalf("expected valid resolver list, invalid=%v", result.InvalidEntries)
			}
			if result.NormalizedText != test.want {
				t.Fatalf("normalized text mismatch\nwant:\n%s\ngot:\n%s", test.want, result.NormalizedText)
			}
		})
	}
}
