package inbound

import (
	"slices"
	"testing"

	"github.com/metacubex/mihomo/common/structure"
)

// The listener decoder uses the inbound tag, so this pins both the current
// spellings and the legacy ones to the field that receives them. Underscore
// spellings are accepted through DefaultKeyReplacer, like every other key.
func TestEBPFOptionDecodesPortKeySpellings(t *testing.T) {
	decoder := structure.NewDecoder(structure.Option{
		TagName:          "inbound",
		WeaklyTypedInput: true,
		KeyReplacer:      structure.DefaultKeyReplacer,
	})
	for _, testCase := range []struct {
		name  string
		key   string
		value any
		check func(*testing.T, EBPFOption)
	}{
		{
			name:  "exclude-port",
			key:   "exclude-port",
			value: []any{22},
			check: func(t *testing.T, option EBPFOption) {
				if !slices.Equal(option.Local.ExcludePort, []string{"22"}) || len(option.Local.LegacyBypassPort) != 0 {
					t.Fatalf("exclude-port was not the current key: %+v", option.Local)
				}
			},
		},
		{
			name:  "exclude_port",
			key:   "exclude_port",
			value: []any{22},
			check: func(t *testing.T, option EBPFOption) {
				if !slices.Equal(option.Local.ExcludePort, []string{"22"}) {
					t.Fatalf("exclude_port was not the current key: %+v", option.Local)
				}
			},
		},
		{
			name:  "exclude-port range",
			key:   "exclude-port",
			value: []any{"1000-2000"},
			check: func(t *testing.T, option EBPFOption) {
				if !slices.Equal(option.Local.ExcludePort, []string{"1000-2000"}) {
					t.Fatalf("exclude-port dropped a range entry: %+v", option.Local)
				}
			},
		},
		{
			name:  "include-port",
			key:   "include-port",
			value: []any{443},
			check: func(t *testing.T, option EBPFOption) {
				if !slices.Equal(option.Local.IncludePort, []string{"443"}) {
					t.Fatalf("include-port was not decoded: %+v", option.Local)
				}
			},
		},
		{
			name:  "bypass-port",
			key:   "bypass-port",
			value: []any{22},
			check: func(t *testing.T, option EBPFOption) {
				if !slices.Equal(option.Local.LegacyBypassPort, []uint16{22}) || len(option.Local.ExcludePort) != 0 {
					t.Fatalf("bypass-port was not the legacy key: %+v", option.Local)
				}
			},
		},
		{
			name:  "bypass_port",
			key:   "bypass_port",
			value: []any{22},
			check: func(t *testing.T, option EBPFOption) {
				if !slices.Equal(option.Local.LegacyBypassPort, []uint16{22}) {
					t.Fatalf("bypass_port was not the legacy key: %+v", option.Local)
				}
			},
		},
		{
			name:  "exclude-port-range",
			key:   "exclude-port-range",
			value: []any{"1000:2000"},
			check: func(t *testing.T, option EBPFOption) {
				if !slices.Equal(option.Local.LegacyExcludePortRange, []string{"1000:2000"}) || len(option.Local.ExcludePort) != 0 {
					t.Fatalf("exclude-port-range was not the legacy key: %+v", option.Local)
				}
			},
		},
		{
			name:  "include-port-range",
			key:   "include-port-range",
			value: []any{"8000:8100"},
			check: func(t *testing.T, option EBPFOption) {
				if !slices.Equal(option.Local.LegacyIncludePortRange, []string{"8000:8100"}) || len(option.Local.IncludePort) != 0 {
					t.Fatalf("include-port-range was not the legacy key: %+v", option.Local)
				}
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			option := &EBPFOption{}
			mapping := map[string]any{
				"name":  "ebpf-test",
				"local": map[string]any{testCase.key: testCase.value},
			}
			if err := decoder.Decode(mapping, option); err != nil {
				t.Fatal(err)
			}
			testCase.check(t, *option)
		})
	}
}
