package inbound

import (
	"slices"
	"testing"

	"github.com/metacubex/mihomo/common/structure"
)

// The listener decoder uses the inbound tag, so this pins both the current
// spelling and the legacy one to the field that receives them. Underscore
// spellings are accepted through DefaultKeyReplacer, like every other key.
func TestEBPFOptionDecodesPortKeySpellings(t *testing.T) {
	decoder := structure.NewDecoder(structure.Option{
		TagName:          "inbound",
		WeaklyTypedInput: true,
		KeyReplacer:      structure.DefaultKeyReplacer,
	})
	for _, testCase := range []struct {
		key     string
		current bool
	}{
		{key: "exclude-port", current: true},
		{key: "exclude_port", current: true},
		{key: "bypass-port", current: false},
		{key: "bypass_port", current: false},
	} {
		t.Run(testCase.key, func(t *testing.T) {
			option := &EBPFOption{}
			mapping := map[string]any{
				"name":  "ebpf-test",
				"local": map[string]any{testCase.key: []any{22}},
			}
			if err := decoder.Decode(mapping, option); err != nil {
				t.Fatal(err)
			}
			if testCase.current {
				if !slices.Equal(option.Local.BypassPort, []uint16{22}) ||
					len(option.Local.LegacyBypassPort) != 0 {
					t.Fatalf("%s was not decoded as exclude-port: %+v", testCase.key, option.Local)
				}
				return
			}
			if !slices.Equal(option.Local.LegacyBypassPort, []uint16{22}) ||
				len(option.Local.BypassPort) != 0 {
				t.Fatalf("%s was not decoded as the legacy port key: %+v", testCase.key, option.Local)
			}
		})
	}
}
