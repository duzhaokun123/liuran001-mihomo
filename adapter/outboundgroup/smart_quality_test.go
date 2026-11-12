package outboundgroup

import (
	"errors"
	"testing"

	"github.com/metacubex/mihomo/component/smart"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

func TestUDPFailuresDoNotBlockTCP(t *testing.T) {
	smart.InitCache()
	smart.InitQueue()
	s := sweepGroup("udp-isolation")
	s.configName = "config"
	s.store = &smart.Store{}
	s.maxFailedTimes = 1
	s.hostFailLimit.Store(100)
	metadata := &C.Metadata{NetWork: C.UDP, Host: "udp.example.com", WildcardTarget: "*.example.com", SmartTarget: "service"}
	s.markNodeFailure(metadata, "node", true, true, smart.BlockDialFailure, 0)
	for _, target := range []string{metadata.WildcardTarget, metadata.SmartTarget} {
		tcp, _, _, _ := s.store.GetHostStatus(s.Name(), s.configName, target, 100)
		require.NotContains(t, tcp, "node", "UDP failure contaminated TCP selection")
		udp, _, _, _ := s.store.GetHostStatus(s.Name(), s.configName, smart.NetScopedTarget(target, true), 100)
		require.Equal(t, smart.BlockDialFailure, udp["node"])
	}
	// A TCP success cannot erase evidence about a UDP-only failure.
	metadata.NetWork = C.TCP
	s.markNodeFailure(metadata, "node", false, true, smart.BlockNone, 0)
	udp, _, _, _ := s.store.GetHostStatus(s.Name(), s.configName, smart.NetScopedTarget(metadata.SmartTarget, true), 100)
	require.Equal(t, smart.BlockDialFailure, udp["node"])
}

func TestStalledHostDoesNotExcludeWholeRule(t *testing.T) {
	smart.InitCache()
	smart.InitQueue()
	s := sweepGroup("stall-scope")
	s.configName = "config"
	s.store = &smart.Store{}
	s.hostFailLimit.Store(100)
	metadata := &C.Metadata{NetWork: C.TCP, WildcardTarget: "*.example.com", SmartTarget: "service"}
	s.markNodeFailure(metadata, "node", true, true, smart.BlockStalled, stalledProbeTTL)
	host, _, _, _ := s.store.GetHostStatus(s.Name(), s.configName, metadata.WildcardTarget, 100)
	require.Equal(t, smart.BlockStalled, host["node"])
	rule, _, _, _ := s.store.GetHostStatus(s.Name(), s.configName, metadata.SmartTarget, 100)
	require.NotContains(t, rule, "node", "one stalled host excluded every host in the rule")
}

// The rule is meant to catch a node that accepts a flow and then swallows it.
// Requiring zero upload inverted the attribution: if the client never sent a
// byte the node had nothing to answer, so every speculative TLS connection a
// browser opens and closes unused cost the node a 24-hour block. The fork's
// own stall detector draws the line the same way.
func TestNoResponseVerdictNeedsTheClientToHaveSentSomething(t *testing.T) {
	const (
		group          = "quality-group"
		config         = "config"
		wildcardTarget = "example.com"
		node           = "node-a"
	)
	smart.InitCache()
	smart.InitQueue()

	for _, testCase := range []struct {
		name         string
		uploadTotal  float64
		wantDegraded bool
		wantCode     smart.BlockCode
	}{
		{name: "client sent nothing", uploadTotal: 0, wantDegraded: false, wantCode: smart.BlockNone},
		{name: "client sent a request and got nothing back", uploadTotal: 1, wantDegraded: true, wantCode: smart.BlockStalled},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			s := sweepGroup(group + testCase.name)
			s.configName = config
			s.store = &smart.Store{}
			s.maxFailedTimes = 3
			s.hostFailLimit.Store(1_000)

			// Host is empty so the abnormal-status branch below cannot run a
			// live StatusTest through a nil proxy.
			metadata := &C.Metadata{
				WildcardTarget: wildcardTarget, SmartBlock: "normal",
				NetWork: C.TCP, DstPort: 443,
			}
			_, isDegraded, _, blockCode, _ := s.checkNodeQuality(s.readTargetState(metadata, node), metadata, blameTestProxy{name: node}, connQuality{err: nil, address: "example.com:443", weight: 0.9, oldWeight: 0.9, duration: 5_000, uploadMB: testCase.uploadTotal, downloadMB: 0})

			if isDegraded != testCase.wantDegraded || blockCode != testCase.wantCode {
				t.Fatalf("degraded=%v code=%d, want %v and %d",
					isDegraded, blockCode, testCase.wantDegraded, testCase.wantCode)
			}
		})
	}
}

// blameTestProxy reports a type recordConnectionStats returns on immediately,
// so the test exercises the markCloseFailure branch alone.
type blameTestProxy struct {
	C.Proxy
	name string
}

func (p blameTestProxy) Name() string        { return p.name }
func (p blameTestProxy) Type() C.AdapterType { return C.Reject }

// A node that accepts the flow and closes it before answering anything is a
// failure no dial error reports: the close arrives as a clean EOF, so the
// connection used to be counted as a success. The client has to have sent
// something, the node has to be the side that closed, and the close has to be
// immediate -- past the stall window the existing blocked-stalled rule owns it.
func TestEarlyCloseNeedsAPeerCloseWithSentData(t *testing.T) {
	const (
		group          = "early-close"
		config         = "config"
		wildcardTarget = "example.com"
		node           = "node-a"
	)
	smart.InitCache()
	smart.InitQueue()

	for _, testCase := range []struct {
		name         string
		peerClosed   bool
		network      C.NetWork
		duration     int64
		uploadMB     float64
		downloadMB   float64
		wantEarly    bool
		wantDegraded bool
		wantCode     smart.BlockCode
	}{
		{name: "peer closed immediately without an answer", peerClosed: true, network: C.TCP, duration: 1_000, uploadMB: 1, wantEarly: true, wantCode: smart.BlockNone},
		{name: "the client closed instead", peerClosed: false, network: C.TCP, duration: 1_000, uploadMB: 1, wantCode: smart.BlockNone},
		{name: "the client never sent anything", peerClosed: true, network: C.TCP, duration: 1_000, downloadMB: 0, wantCode: smart.BlockNone},
		{name: "something did come back", peerClosed: true, network: C.TCP, duration: 1_000, uploadMB: 1, downloadMB: 1, wantCode: smart.BlockNone},
		{name: "the flow lived past the stall window", peerClosed: true, network: C.TCP, duration: 5_000, uploadMB: 1, wantDegraded: true, wantCode: smart.BlockStalled},
		{name: "udp has no early close", peerClosed: true, network: C.UDP, duration: 1_000, uploadMB: 1, wantCode: smart.BlockNone},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			s := sweepGroup(group + testCase.name)
			s.configName = config
			s.store = &smart.Store{}
			s.maxFailedTimes = 3
			s.hostFailLimit.Store(1_000)

			// Host is empty so the response-probe branch cannot dispatch a live
			// probe through a nil proxy; the node identity is all this judges.
			metadata := &C.Metadata{
				WildcardTarget: wildcardTarget, SmartBlock: "normal",
				NetWork: testCase.network, DstPort: 443,
			}
			_, degraded, _, blockCode, earlyClose := s.checkNodeQuality(
				s.readTargetState(metadata, node), metadata, blameTestProxy{name: node},
				connQuality{peerClosed: testCase.peerClosed, weight: 0.9, oldWeight: 0.9,
					duration: testCase.duration, uploadMB: testCase.uploadMB, downloadMB: testCase.downloadMB})

			if earlyClose != testCase.wantEarly || degraded != testCase.wantDegraded || blockCode != testCase.wantCode {
				t.Fatalf("earlyClose=%v degraded=%v code=%d, want earlyClose=%v degraded=%v code=%d",
					earlyClose, degraded, blockCode, testCase.wantEarly, testCase.wantDegraded, testCase.wantCode)
			}
		})
	}
}

// The penalty has to reach the placement the dial path actually follows: the
// stored weight is what the prefetch is built from, and the prefetch is what a
// dial reads first. Dropping the pin alone would leave the stale prefetch
// steering the target back onto the same node.
func TestEarlyCloseHalvesTheStoredWeightAndSteersAway(t *testing.T) {
	const (
		group  = "early-close-weight"
		config = "config"
		target = "example.com"
		node   = "node-a"
		peer   = "node-b"
	)
	smart.InitCache()
	smart.InitQueue()

	s := sweepGroup(group)
	s.configName = config
	s.store = &smart.Store{}
	s.maxFailedTimes = 3
	s.hostFailLimit.Store(1_000)

	proxy := strategyTestProxy{name: node, alive: true}
	metadata := &C.Metadata{
		Host: "early.example.com", WildcardTarget: "*.example.com",
		SmartTarget: target, SmartBlock: "normal", NetWork: C.TCP, DstPort: 443,
	}

	cacheKey := smart.FormatDBKey(smart.KeyTypeStats, config, group, target, node)
	record := s.store.GetOrCreateAtomicRecord(cacheKey, group, config, target, node)
	record.AddSuccess(2)
	record.SetWeight(smart.WeightTypeTCP, 0.8)

	s.store.StoreUnwrapResult(group, config, target, []C.Proxy{proxy})
	s.store.StorePrefetchResult(group, config, target, false, []string{node, peer}, []float64{0.8, 0.7})

	// A dial that succeeded, carried 1KB up, heard nothing, and was closed by
	// the node after half a second.
	s.recordConnectionStats(metadata, proxy, 50, 20, 1024, 0, 0, 0, 500, nil, nil, nil, true)

	require.InDelta(t, 0.4, record.GetWeight(smart.WeightTypeTCP), 1e-9,
		"an early close has to halve the stored weight, not nudge it through the EMA")

	if pinned, _ := s.store.GetUnwrapResult(group, config, target); len(pinned) != 0 {
		t.Fatalf("the target stayed pinned to the node that closed the flow: %v", pinned)
	}

	nodes, weights := s.store.GetPrefetchResult(group, config, target, false)
	require.Equal(t, []string{peer, node}, nodes, "the prefetch still puts the penalized node first")
	require.InDelta(t, 0.4, weights[1], 1e-9)

	failNodes, _, _, _ := s.store.GetHostStatus(group, config, metadata.WildcardTarget, 1_000)
	require.NotContains(t, failNodes, node, "the early close is a weight penalty, not a host block")
}

// A connection this group closed itself says nothing about the node that
// carried it. checkNodeQuality honours the degraded marker; the close-failure
// path did not, so a victim whose first read had already failed before the
// sweep reached it was blamed anyway.
func TestASweptConnectionIsNotBlamedForItsCloseError(t *testing.T) {
	const (
		config         = "config"
		wildcardTarget = "example.com"
		node           = "node-a"
	)
	smart.InitCache()
	smart.InitQueue()

	for _, testCase := range []struct {
		name       string
		smartBlock string
		wantBlamed bool
	}{
		{name: "closed by this group", smartBlock: "degraded", wantBlamed: false},
		{name: "closed by the network", smartBlock: "normal", wantBlamed: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			group := "blame-group-" + testCase.name
			s := sweepGroup(group)
			s.configName = config
			s.store = &smart.Store{}
			s.maxFailedTimes = 1

			metadata := &C.Metadata{
				Host: "probe.example.com", WildcardTarget: wildcardTarget,
				SmartBlock: testCase.smartBlock, NetWork: C.TCP,
			}
			if !s.submitConnectionStats(metadata, blameTestProxy{name: node},
				0, 0, 0, 0, 0, 0, 1_000, nil, nil, errors.New("connection reset"), false, true) {
				t.Fatal("submission was refused")
			}
			s.workWG.Wait()

			failNodes, _, _, _ := s.store.GetHostStatus(group, config, wildcardTarget, 1_000)
			if blamed := failNodes[node] != 0; blamed != testCase.wantBlamed {
				t.Fatalf("blamed=%v (code %d), want %v", blamed, failNodes[node], testCase.wantBlamed)
			}
		})
	}
}
