//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"slices"
	"testing"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
)

func TestParsePortRanges(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		specs []string
		want  []ECommon.PortRange
	}{
		{name: "empty", specs: nil},
		{name: "single port", specs: []string{"22"}, want: []ECommon.PortRange{{Start: 22, End: 22}}},
		{name: "upper boundary", specs: []string{"65535"}, want: []ECommon.PortRange{{Start: 65535, End: 65535}}},
		{name: "range", specs: []string{"1000-2000"}, want: []ECommon.PortRange{{Start: 1000, End: 2000}}},
		{name: "single-value range", specs: []string{"443-443"}, want: []ECommon.PortRange{{Start: 443, End: 443}}},
		{
			name:  "mixed spellings",
			specs: []string{"443", "8000-8100", "22"},
			want:  []ECommon.PortRange{{Start: 22, End: 22}, {Start: 443, End: 443}, {Start: 8000, End: 8100}},
		},
		{
			name:  "adjacent ranges merge",
			specs: []string{"1-5", "6-9"},
			want:  []ECommon.PortRange{{Start: 1, End: 9}},
		},
		{
			name:  "overlapping ranges merge",
			specs: []string{"10-20", "15-30"},
			want:  []ECommon.PortRange{{Start: 10, End: 30}},
		},
		{
			name:  "duplicates collapse",
			specs: []string{"53", "53", "53-53"},
			want:  []ECommon.PortRange{{Start: 53, End: 53}},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := parsePortRanges("local.exclude_port", testCase.specs)
			if err != nil {
				t.Fatalf("rejected a valid policy: %v", err)
			}
			if !slices.Equal(got, testCase.want) {
				t.Fatalf("got %+v, want %+v", got, testCase.want)
			}
		})
	}
}

func TestParsePortRangesRejectsNonsense(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		specs []string
	}{
		{name: "empty entry", specs: []string{""}},
		{name: "zero", specs: []string{"0"}},
		{name: "zero start", specs: []string{"0-10"}},
		{name: "zero end", specs: []string{"10-0"}},
		{name: "reversed", specs: []string{"10-5"}},
		{name: "missing start", specs: []string{"-5"}},
		{name: "missing end", specs: []string{"1-"}},
		{name: "overflow", specs: []string{"65536"}},
		{name: "range overflow", specs: []string{"1-65536"}},
		{name: "letters", specs: []string{"a-b"}},
		{name: "trailing junk", specs: []string{"22x"}},
		{name: "spaces", specs: []string{" 22"}},
		{name: "old separator", specs: []string{"1000:2000"}},
		{name: "one bad entry", specs: []string{"22", "bad"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got, err := parsePortRanges("local.exclude_port", testCase.specs); err == nil {
				t.Fatalf("accepted %q as %+v", testCase.specs, got)
			}
		})
	}
}
