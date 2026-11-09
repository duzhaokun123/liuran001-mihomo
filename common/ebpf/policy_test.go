//go:build with_ebpf && (linux || android)

package ebpf

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"unsafe"
)

func TestCompileUIDRanges(t *testing.T) {
	if size := unsafe.Sizeof(uidLPMKey{}); size != 8 {
		t.Fatalf("unexpected UID LPM key size: %d", size)
	}
	entries := compileUIDRanges([]UIDRange{
		{Start: 0, End: 0},
		{Start: 1000, End: 99999},
	})
	for _, uid := range []uint32{0, 1000, 50000, 99999} {
		if !uidMatchesPrefixes(uid, entries) {
			t.Fatalf("UID %d is not covered", uid)
		}
	}
	for _, uid := range []uint32{1, 999, 100000} {
		if uidMatchesPrefixes(uid, entries) {
			t.Fatalf("UID %d is unexpectedly covered", uid)
		}
	}
}

func TestCompileFullUIDRange(t *testing.T) {
	entries := compileUIDRanges([]UIDRange{{Start: 0, End: ^uint32(0)}})
	if len(entries) != 1 || entries[0].PrefixLength != 0 {
		t.Fatalf("unexpected full UID range: %+v", entries)
	}
}

func TestCompileUIDPolicyPrecedence(t *testing.T) {
	entries, defaultBypass, err := compileUIDPolicy(LocalPolicy{
		IncludeUIDConfigured: true,
		IncludeUID:           []UIDRange{{Start: 1000, End: 1999}},
		ExcludeUID:           []UIDRange{{Start: 1200, End: 1299}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !defaultBypass {
		t.Fatal("include policy did not enable default bypass")
	}
	for _, uid := range []uint32{1000, 1199, 1300, 1999} {
		if !uidMatchesPrefixes(uid, entries) {
			t.Fatalf("UID %d is not included", uid)
		}
	}
	for _, uid := range []uint32{999, 1200, 1299, 2000} {
		if uidMatchesPrefixes(uid, entries) {
			t.Fatalf("UID %d is unexpectedly included", uid)
		}
	}
}

func TestCompileEmptyConfiguredUIDPolicy(t *testing.T) {
	entries, defaultBypass, err := compileUIDPolicy(LocalPolicy{IncludeUIDConfigured: true})
	if err != nil {
		t.Fatal(err)
	}
	if !defaultBypass || len(entries) != 0 {
		t.Fatalf("unexpected empty include policy: default_bypass=%v entries=%v", defaultBypass, entries)
	}
}

func TestCompileExcludeOnlyUIDPolicy(t *testing.T) {
	entries, defaultBypass, err := compileUIDPolicy(LocalPolicy{
		ExcludeUID: []UIDRange{{Start: 1000, End: 1999}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if defaultBypass || !uidMatchesPrefixes(1500, entries) || uidMatchesPrefixes(2000, entries) {
		t.Fatalf("unexpected exclude policy: default_bypass=%v entries=%v", defaultBypass, entries)
	}
}

func TestCompileUID1052UsesConfiguredPolicy(t *testing.T) {
	entries, defaultBypass, err := compileUIDPolicy(LocalPolicy{
		ExcludeUID: []UIDRange{{Start: 1052, End: 1052}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if defaultBypass || !uidMatchesPrefixes(1052, entries) {
		t.Fatalf("UID 1052 was not handled as a configured exclusion: default_bypass=%v entries=%v", defaultBypass, entries)
	}

	entries, defaultBypass, err = compileUIDPolicy(LocalPolicy{
		IncludeUIDConfigured: true,
		IncludeUID:           []UIDRange{{Start: 1052, End: 1052}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !defaultBypass || !uidMatchesPrefixes(1052, entries) {
		t.Fatalf("UID 1052 was not handled as a configured inclusion: default_bypass=%v entries=%v", defaultBypass, entries)
	}
}

func TestCompileBypassCIDRPolicy(t *testing.T) {
	ipv4, ipv6, err := compileBypassCIDRPolicy([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/9"),
		netip.MustParsePrefix("10.128.0.0/9"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("::ffff:192.0.2.0/120"),
		netip.MustParsePrefix("2001:db8::/33"),
		netip.MustParsePrefix("2001:db8:8000::/33"),
	})
	if err != nil {
		t.Fatal(err)
	}
	expectedIPv4 := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.0.2.0/24"),
	}
	expectedIPv6 := []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}
	if !equalPrefixes(ipv4, expectedIPv4) || !equalPrefixes(ipv6, expectedIPv6) {
		t.Fatalf("unexpected compiled CIDRs: IPv4=%v IPv6=%v", ipv4, ipv6)
	}
}

func TestCompilePolicySnapshot(t *testing.T) {
	includeUID := []UIDRange{{Start: 1000, End: 1002}}
	includeSource := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	includeMAC := []MACAddress{{0x02, 0, 0, 0, 0, 1}}
	policy, err := CompilePolicy(PolicyConfig{
		EnableTCP:           true,
		EnableUDP:           true,
		Local:               LocalPolicy{IncludeUID: includeUID},
		SharedDNSMode:       DNSModeRespectPolicy,
		SharedBypassPrivate: true,
		FakeIPIPv4:          netip.MustParsePrefix("198.18.1.1/15"),
		IncludeSourceCIDR:   includeSource,
		IncludeSourceMAC:    includeMAC,
		LocalBypassPort:     []PortRange{{Start: 443, End: 443}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.uidEntries) == 0 || !policy.uidDefaultBypass ||
		len(policy.includeSource.ipv4) != 1 || len(policy.includeSourceMAC) != 1 ||
		len(policy.localBypassPortEntries) != 2 {
		t.Fatalf("compiled policy omitted configured rules: %+v", policy)
	}
	if policy.fakeIPIPv4 != netip.MustParsePrefix("198.18.0.0/15") {
		t.Fatalf("FakeIP prefix was not normalized: %s", policy.fakeIPIPv4)
	}
	includeUID[0].Start = 2000
	includeSource[0] = netip.MustParsePrefix("203.0.113.0/24")
	includeMAC[0][0] = 0x06
	if policy.local.IncludeUID[0].Start != 1000 ||
		policy.includeSource.ipv4[0] != netip.MustParsePrefix("192.0.2.0/24") ||
		policy.includeSourceMAC[0][0] != 0x02 {
		t.Fatal("compiled policy retained mutable input slices")
	}
}

func TestBypassCIDRPolicyDelta(t *testing.T) {
	current := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.0.2.0/24"),
	}
	next := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("198.51.100.0/24"),
	}
	additions, removals := bypassCIDRPolicyDelta(current, next)
	if !equalPrefixes(additions, next[1:]) || !equalPrefixes(removals, current[1:]) {
		t.Fatalf("unexpected CIDR delta: additions=%v removals=%v", additions, removals)
	}
}

func equalPrefixes(left []netip.Prefix, right []netip.Prefix) bool {
	return slices.Equal(left, right)
}

func uidMatchesPrefixes(uid uint32, entries []uidLPMKey) bool {
	for _, entry := range entries {
		prefix := binary.BigEndian.Uint32(entry.UID[:])
		if entry.PrefixLength == 0 || uid>>(32-entry.PrefixLength) == prefix>>(32-entry.PrefixLength) {
			return true
		}
	}
	return false
}

func TestCompilePortPolicyIncludeMode(t *testing.T) {
	entries, include, err := compilePortPolicy("local",
		[]PortRange{{Start: 443, End: 443}}, nil, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if !include {
		t.Fatal("an include list did not select include mode")
	}
	if len(entries) != 2 || entries[0] != (tcPortKey{Protocol: ProtocolTCP, Port: 443}) ||
		entries[1] != (tcPortKey{Protocol: ProtocolUDP, Port: 443}) {
		t.Fatalf("unexpected include entries: %+v", entries)
	}

	entries, include, err = compilePortPolicy("local", nil,
		[]PortRange{{Start: 22, End: 22}}, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if include {
		t.Fatal("a bypass list selected include mode")
	}
	if len(entries) != 1 || entries[0] != (tcPortKey{Protocol: ProtocolTCP, Port: 22}) {
		t.Fatalf("unexpected bypass entries: %+v", entries)
	}
}

func TestCompilePortPolicyMutualExclusion(t *testing.T) {
	_, _, err := compilePortPolicy("shared",
		[]PortRange{{Start: 443, End: 443}}, []PortRange{{Start: 22, End: 22}}, true, true)
	if err == nil {
		t.Fatal("include and bypass port lists were accepted together")
	}
	if message := err.Error(); !strings.Contains(message, "mutually exclusive") ||
		!strings.Contains(message, "shared") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCompilePortPolicyCapacityReportsEntryCount(t *testing.T) {
	// One wide range with both protocols enabled compiles to twice the port
	// count, which is what the map capacity limits.
	_, _, err := compilePortPolicy("local", []PortRange{{Start: 1, End: 4096}}, nil, true, true)
	if err == nil {
		t.Fatal("oversized port policy was accepted")
	}
	if message := err.Error(); !strings.Contains(message, "8192 > 4096") {
		t.Fatalf("capacity error did not report the compiled entry count: %v", err)
	}
	if _, _, err := compilePortPolicy("local", []PortRange{{Start: 0, End: 22}}, nil, true, true); err == nil {
		t.Fatal("port 0 was accepted")
	}
}

func TestCompilePolicyIncludePortSnapshot(t *testing.T) {
	policy, err := CompilePolicy(PolicyConfig{
		EnableTCP:        true,
		LocalIncludePort: []PortRange{{Start: 443, End: 443}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !policy.localPortInclude || policy.sharedPortInclude {
		t.Fatalf("include mode leaked across roles: %+v", policy)
	}
	if len(policy.localBypassPortEntries) != 1 ||
		policy.localBypassPortEntries[0] != (tcPortKey{Protocol: ProtocolTCP, Port: 443}) {
		t.Fatalf("unexpected local port entries: %+v", policy.localBypassPortEntries)
	}
	if len(policy.sharedBypassPortEntries) != 0 {
		t.Fatalf("shared role kept local entries: %+v", policy.sharedBypassPortEntries)
	}
}
