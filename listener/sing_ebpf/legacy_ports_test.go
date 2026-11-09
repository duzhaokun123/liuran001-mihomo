//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"slices"
	"strings"
	"testing"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
	LC "github.com/metacubex/mihomo/listener/config"
)

// Every older port spelling folds into the merged exclude-port/include-port
// lists so configs written before the merge keep working, with the current key
// winning if both appear.
func TestLegacyPortKeysFoldIntoMergedLists(t *testing.T) {
	options, notes, err := applyLegacyOptions(LC.EBPF{
		Mode: "hybrid",
		Local: LC.EBPFLocal{
			LegacyBypassPort:       []uint16{22},
			LegacyBypassPortRange:  []string{"1000:2000"},
			LegacyExcludePortRange: []string{"3000:3100"},
			LegacyIncludePortRange: []string{"443:443"},
		},
		Shared: LC.EBPFShared{LegacyBypassPort: []uint16{53}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(options.Local.ExcludePort, []string{"22", "1000-2000", "3000-3100"}) {
		t.Errorf("local legacy port keys were not folded into exclude-port: %v", options.Local.ExcludePort)
	}
	if !slices.Equal(options.Local.IncludePort, []string{"443-443"}) {
		t.Errorf("local.include-port-range was not folded into include-port: %v", options.Local.IncludePort)
	}
	if !slices.Equal(options.Shared.ExcludePort, []string{"53"}) {
		t.Errorf("shared.bypass-port was not folded into exclude-port: %v", options.Shared.ExcludePort)
	}
	if len(notes) != 5 {
		t.Errorf("expected one note per legacy key, got %d: %v", len(notes), notes)
	}
	for _, note := range notes {
		if !strings.Contains(note, "is deprecated") {
			t.Errorf("a note does not say the legacy key is deprecated: %q", note)
		}
	}

	// The folded spellings must be what the current parser reads.
	parsed, err := parsePortRanges("local.exclude_port", options.Local.ExcludePort)
	if err != nil {
		t.Fatalf("folded exclude-port entries rejected: %v", err)
	}
	if !slices.Equal(parsed, []ECommon.PortRange{
		{Start: 22, End: 22},
		{Start: 1000, End: 2000},
		{Start: 3000, End: 3100},
	}) {
		t.Errorf("unexpected folded ranges: %+v", parsed)
	}
}

func TestMergedPortKeyWinsOverLegacyKeys(t *testing.T) {
	options, notes, err := applyLegacyOptions(LC.EBPF{
		Mode: "local",
		Local: LC.EBPFLocal{
			ExcludePort:            []string{"443"},
			IncludePort:            []string{"8443"},
			LegacyBypassPort:       []uint16{22},
			LegacyBypassPortRange:  []string{"9000:9100"},
			LegacyExcludePortRange: []string{"9100:9200"},
			LegacyIncludePortRange: []string{"9443:9443"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(options.Local.ExcludePort, []string{"443"}) {
		t.Errorf("exclude-port was overridden by a legacy key: %v", options.Local.ExcludePort)
	}
	if !slices.Equal(options.Local.IncludePort, []string{"8443"}) {
		t.Errorf("include-port was overridden by a legacy key: %v", options.Local.IncludePort)
	}
	if len(notes) != 4 {
		t.Fatalf("expected one note per ignored legacy key, got %d: %v", len(notes), notes)
	}
	for _, note := range notes {
		if !strings.Contains(note, "was ignored") {
			t.Errorf("a note does not say the legacy key was ignored: %q", note)
		}
	}
}

func TestLegacyPortKeysInDisabledRoleAreSilentlyDropped(t *testing.T) {
	options, notes, err := applyLegacyOptions(LC.EBPF{
		Mode: "local",
		Shared: LC.EBPFShared{
			LegacyBypassPort:       []uint16{53},
			LegacyExcludePortRange: []string{"1000:2000"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) != 0 {
		t.Errorf("a disabled role produced legacy notes: %v", notes)
	}
	if len(options.Shared.ExcludePort) != 0 || len(options.Shared.LegacyBypassPort) != 0 {
		t.Errorf("a disabled role kept a port policy: %+v", options.Shared)
	}
}
