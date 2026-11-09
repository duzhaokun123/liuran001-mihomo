//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"slices"
	"strings"
	"testing"

	LC "github.com/metacubex/mihomo/listener/config"
)

// The rename from bypass-port to exclude-port keeps the old spelling working
// for configs written before it, with the current key winning if both appear.
func TestLegacyPortKeysFoldIntoExcludePort(t *testing.T) {
	options, notes, err := applyLegacyOptions(LC.EBPF{
		Mode: "hybrid",
		Local: LC.EBPFLocal{
			LegacyBypassPort:      []uint16{22},
			LegacyBypassPortRange: []string{"1000:2000"},
		},
		Shared: LC.EBPFShared{LegacyBypassPort: []uint16{53}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(options.Local.BypassPort, []uint16{22}) {
		t.Errorf("local.bypass-port was not folded into exclude-port: %v", options.Local.BypassPort)
	}
	if !slices.Equal(options.Local.BypassPortRange, []string{"1000:2000"}) {
		t.Errorf("local.bypass-port-range was not folded into exclude-port-range: %v", options.Local.BypassPortRange)
	}
	if !slices.Equal(options.Shared.BypassPort, []uint16{53}) {
		t.Errorf("shared.bypass-port was not folded into exclude-port: %v", options.Shared.BypassPort)
	}
	if len(notes) != 3 {
		t.Errorf("expected one note per legacy key, got %d: %v", len(notes), notes)
	}
}

func TestExcludePortWinsOverLegacyBypassPort(t *testing.T) {
	options, notes, err := applyLegacyOptions(LC.EBPF{
		Mode: "local",
		Local: LC.EBPFLocal{
			BypassPort:            []uint16{443},
			BypassPortRange:       []string{"8000:8100"},
			LegacyBypassPort:      []uint16{22},
			LegacyBypassPortRange: []string{"9000:9100"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(options.Local.BypassPort, []uint16{443}) {
		t.Errorf("exclude-port was overridden by the legacy key: %v", options.Local.BypassPort)
	}
	if !slices.Equal(options.Local.BypassPortRange, []string{"8000:8100"}) {
		t.Errorf("exclude-port-range was overridden by the legacy key: %v", options.Local.BypassPortRange)
	}
	if len(notes) != 2 {
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
		Mode:   "local",
		Shared: LC.EBPFShared{LegacyBypassPort: []uint16{53}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) != 0 {
		t.Errorf("a disabled role produced legacy notes: %v", notes)
	}
	if len(options.Shared.BypassPort) != 0 || len(options.Shared.LegacyBypassPort) != 0 {
		t.Errorf("a disabled role kept a port policy: %+v", options.Shared)
	}
}
