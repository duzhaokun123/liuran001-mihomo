package smart

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// A prefetch entry carries both networks in one record. The penalty has to
// rewrite the TCP side without dropping the UDP side on the floor, which is
// what StorePrefetchResult would do: it writes a map holding only one network.
func TestPenalizePrefetchWeightKeepsBothNetworks(t *testing.T) {
	InitCache()
	InitQueue()

	store := &Store{}
	data, err := json.Marshal(PrefetchMap{
		TCP: NodesWithWeights{Nodes: []string{"a", "b"}, Weights: []float64{0.8, 0.7}},
		UDP: NodesWithWeights{Nodes: []string{"a", "b"}, Weights: []float64{0.9, 0.6}},
	})
	require.NoError(t, err)
	store.AppendToGlobalQueue(StoreOperation{
		Type:   OpSavePrefetch,
		Group:  "penalty-group",
		Config: "penalty-config",
		Target: "penalty-target",
		Data:   data,
	})

	store.PenalizePrefetchWeight("penalty-group", "penalty-config", "penalty-target", false, "a", 0.5)

	tcpNodes, tcpWeights := store.GetPrefetchResult("penalty-group", "penalty-config", "penalty-target", false)
	require.Equal(t, []string{"b", "a"}, tcpNodes, "the penalized node kept its place at the front")
	require.InDelta(t, 0.4, tcpWeights[1], 1e-9)

	udpNodes, udpWeights := store.GetPrefetchResult("penalty-group", "penalty-config", "penalty-target", true)
	require.Equal(t, []string{"a", "b"}, udpNodes, "the TCP penalty rewrote the UDP entry")
	require.Equal(t, []float64{0.9, 0.6}, udpWeights)
}
