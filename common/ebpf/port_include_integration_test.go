//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"net/netip"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
)

// An include policy whitelists destination ports: only the listed ports are
// intercepted, everything else is left alone. Local and shared roles carry
// independent lists, and DNS is switched off here so the port decision is the
// only thing selecting a flow.
func TestPortIncludePoliciesIntegration(t *testing.T) {
	requireEBPFIntegration(t, "run include-port whitelists on both TC paths")
	requireTCSocketAssignment(t)
	policy, err := CompilePolicy(PolicyConfig{
		EnableTCP:         true,
		Local:             LocalPolicy{DNSMode: DNSModeOff},
		SharedDNSMode:     DNSModeOff,
		LocalIncludePort:  []PortRange{{Start: 443, End: 443}},
		SharedIncludePort: []PortRange{{Start: 8080, End: 8080}},
	})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := PrepareTC(TCConfig{
		ListenerPort: 65527,
		EnableLocal:  true,
		EnableShared: true,
		EnableIPv4:   true,
		EnableTCP:    true,
		Policy:       policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err = backend.Enable(); err != nil {
		t.Fatal(err)
	}
	// Selection on the local path hands the packet to the delivery
	// interface, so without one nothing would look selected.
	if err = backend.SetDeliveryInterface(1, MACAddress{0x02, 0, 0, 0, 0, 9}); err != nil {
		t.Fatal(err)
	}
	localEgress := backend.runtime.programs[tcProgramLocalEgressEthernet]
	sharedIngress := backend.runtime.programs[tcProgramSharedIngressEthernet]

	source := netip.MustParseAddr("192.0.2.10")
	destination := netip.MustParseAddr("203.0.113.20")
	sourcePort := uint16(52300)
	selected := func(program *CiliumEBPF.Program, destinationPort uint16) bool {
		t.Helper()
		sourcePort++
		action, _ := runTCProgram(t,
			program,
			testIPv4TCPPacket(source, destination, sourcePort, destinationPort))
		return action != testTCActUnspec
	}

	for _, tt := range []struct {
		name   string
		path   string
		port   uint16
		expect bool
	}{
		{"local listed port", "local", 443, true},
		{"local unlisted port", "local", 22, false},
		{"shared listed port", "shared", 8080, true},
		{"shared unlisted port", "shared", 443, false},
	} {
		program := localEgress
		if tt.path == "shared" {
			program = sharedIngress
		}
		if got := selected(program, tt.port); got != tt.expect {
			t.Fatalf("%s: port %d selected=%v, want %v", tt.name, tt.port, got, tt.expect)
		}
	}
}

// A role without a port policy keeps intercepting every port, so the include
// flag cannot leak from the other role through the shared policy vector.
func TestPortIncludeScopesStayIndependentIntegration(t *testing.T) {
	requireEBPFIntegration(t, "run an include whitelist beside an unconfigured role")
	requireTCSocketAssignment(t)
	policy, err := CompilePolicy(PolicyConfig{
		EnableTCP:        true,
		Local:            LocalPolicy{DNSMode: DNSModeOff},
		SharedDNSMode:    DNSModeOff,
		LocalIncludePort: []PortRange{{Start: 443, End: 443}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if policy.sharedPortInclude {
		t.Fatal("include mode leaked into the shared role")
	}
	backend, err := PrepareTC(TCConfig{
		ListenerPort: 65526,
		EnableLocal:  true,
		EnableShared: true,
		EnableIPv4:   true,
		EnableTCP:    true,
		Policy:       policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err = backend.Enable(); err != nil {
		t.Fatal(err)
	}
	sharedIngress := backend.runtime.programs[tcProgramSharedIngressEthernet]
	action, _ := runTCProgram(t, sharedIngress,
		testIPv4TCPPacket(netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("203.0.113.20"), 52400, 22))
	if action == testTCActUnspec {
		t.Fatal("the shared role inherited the local include whitelist")
	}
}
