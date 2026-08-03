// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the CottenDns client.
// This file (balancer.go) handles connection balancing strategies.
// ==============================================================================
package client

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	BalancingRoundRobinDefault = 0
	BalancingRandom            = 1
	BalancingRoundRobin        = 2
	BalancingLeastLoss         = 3
	BalancingLowestLatency     = 4
	// BalancingMTUWeighted selects active-pool resolvers with probability
	// proportional to their download MTU, so a resolver that can carry 4000-byte
	// downloads receives proportionally more traffic than one capped at 1000.
	BalancingMTUWeighted = 5
	BalancingHighestMTU  = 6
)

type Balancer struct {
	strategy  int
	rrCounter atomic.Uint64
	rngState  atomic.Uint64
	version   atomic.Uint64

	mu       sync.Mutex
	sources  []*Connection
	snapshot atomic.Pointer[balancerSnapshot]
}

type connectionStats struct {
	mu           sync.RWMutex
	sent         uint64
	acked        uint64
	rttMicrosSum uint64
	rttCount     uint64
}

const connectionStatsHalfLifeThreshold = 1000

type balancerSnapshot struct {
	version     uint64
	connections []Connection
	valid       []int
	indexByKey  map[string]int
	stats       []*connectionStats
}

func NewBalancer(strategy int) *Balancer {
	b := &Balancer{strategy: strategy}
	b.rngState.Store(seedRNG())
	return b
}

func (b *Balancer) SetConnections(connections []*Connection) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.sources = connections
	size := len(connections)
	indexByKey := make(map[string]int, size)
	stats := make([]*connectionStats, size)
	copied := make([]Connection, size)

	for idx, conn := range connections {
		if conn == nil {
			continue
		}
		copied[idx] = *conn
		indexByKey[conn.Key] = idx
		stats[idx] = &connectionStats{}
	}

	b.snapshot.Store(&balancerSnapshot{
		version:     b.version.Add(1),
		connections: copied,
		valid:       rebuildValidIndices(copied),
		indexByKey:  indexByKey,
		stats:       stats,
	})
}

func (b *Balancer) ValidCount() int {
	snap := b.snapshot.Load()
	if snap == nil {
		return 0
	}
	return len(snap.valid)
}

func (b *Balancer) GetConnectionByKey(key string) (Connection, bool) {
	snap := b.snapshot.Load()
	if snap == nil || key == "" {
		return Connection{}, false
	}

	idx, ok := snap.indexByKey[key]
	if !ok {
		return Connection{}, false
	}

	return derefConnection(snap.connections, idx)
}

func (b *Balancer) SetConnectionValidity(key string, valid bool) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	snap := b.snapshot.Load()
	if snap == nil {
		return false
	}

	idx, ok := snap.indexByKey[key]
	if !ok {
		return false
	}

	if idx < 0 || idx >= len(snap.connections) {
		return false
	}
	conn := snap.connections[idx]
	if conn.IsValid == valid {
		return ok
	}

	if idx < len(b.sources) && b.sources[idx] != nil {
		b.sources[idx].IsValid = valid
		conn = *b.sources[idx]
	} else {
		conn.IsValid = valid
	}

	connections := append([]Connection(nil), snap.connections...)
	connections[idx] = conn
	b.snapshot.Store(&balancerSnapshot{
		version:     b.version.Add(1),
		connections: connections,
		valid:       rebuildValidIndices(connections),
		indexByKey:  snap.indexByKey,
		stats:       snap.stats,
	})
	return true
}

func (b *Balancer) SetConnectionMTU(key string, uploadBytes int, uploadChars int, downloadBytes int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	snap := b.snapshot.Load()
	if snap == nil {
		return false
	}

	idx, ok := snap.indexByKey[key]
	if !ok || idx < 0 || idx >= len(snap.connections) {
		return false
	}

	conn := snap.connections[idx]
	conn.UploadMTUBytes = uploadBytes
	conn.UploadMTUChars = uploadChars
	conn.DownloadMTUBytes = downloadBytes

	if idx < len(b.sources) && b.sources[idx] != nil {
		b.sources[idx].UploadMTUBytes = uploadBytes
		b.sources[idx].UploadMTUChars = uploadChars
		b.sources[idx].DownloadMTUBytes = downloadBytes
		conn = *b.sources[idx]
	}

	connections := append([]Connection(nil), snap.connections...)
	connections[idx] = conn
	b.snapshot.Store(&balancerSnapshot{
		version:     b.version.Add(1),
		connections: connections,
		valid:       rebuildValidIndices(connections),
		indexByKey:  snap.indexByKey,
		stats:       snap.stats,
	})
	return true
}

func (b *Balancer) RefreshValidConnections() {
	b.mu.Lock()
	defer b.mu.Unlock()

	snap := b.snapshot.Load()
	if snap == nil {
		return
	}

	connections := make([]Connection, len(snap.connections))
	copy(connections, snap.connections)
	for idx, source := range b.sources {
		if source == nil || idx >= len(connections) {
			continue
		}
		connections[idx] = *source
	}

	b.snapshot.Store(&balancerSnapshot{
		version:     b.version.Add(1),
		connections: connections,
		valid:       rebuildValidIndices(connections),
		indexByKey:  snap.indexByKey,
		stats:       snap.stats,
	})
}

func (b *Balancer) SnapshotVersion() uint64 {
	snap := b.snapshot.Load()
	if snap == nil {
		return 0
	}
	return snap.version
}

func (b *Balancer) ReportSend(serverKey string) {
	if stats := b.statsForKey(serverKey); stats != nil {
		stats.mu.Lock()
		stats.sent++
		stats.applyHalfLifeLocked()
		stats.mu.Unlock()
	}
}

func (b *Balancer) ReportSuccess(serverKey string, rtt time.Duration) {
	stats := b.statsForKey(serverKey)
	if stats == nil {
		return
	}

	stats.mu.Lock()
	stats.acked++
	if rtt > 0 {
		stats.rttMicrosSum += uint64(rtt / time.Microsecond)
		stats.rttCount++
	}
	stats.applyHalfLifeLocked()
	stats.mu.Unlock()
}

func (b *Balancer) ResetServerStats(serverKey string) {
	stats := b.statsForKey(serverKey)
	if stats == nil {
		return
	}

	stats.mu.Lock()
	stats.sent = 0
	stats.acked = 0
	stats.rttMicrosSum = 0
	stats.rttCount = 0
	stats.mu.Unlock()
}

// SeedConservativeStats initialises a re-activated resolver with a moderate
// loss score so the balancer does not flood it before it has proven reliability.
// Score = (10-8)*1000/10 = 200, below neutral (500) but not as good as healthy
// peers — traffic is directed at it gradually as its real delivery rate improves.
func (b *Balancer) SeedConservativeStats(serverKey string) {
	stats := b.statsForKey(serverKey)
	if stats == nil {
		return
	}

	stats.mu.Lock()
	stats.sent = 10
	stats.acked = 8
	stats.rttMicrosSum = 0
	stats.rttCount = 0
	stats.mu.Unlock()
}

func (b *Balancer) GetBestConnection() (Connection, bool) {
	snap := b.snapshot.Load()
	if snap == nil || len(snap.valid) == 0 {
		return Connection{}, false
	}

	switch b.strategy {
	case BalancingRandom:
		idx := snap.valid[b.nextRandom()%uint64(len(snap.valid))]
		return derefConnection(snap.connections, idx)
	case BalancingMTUWeighted:
		return b.weightedByMTUConnection(snap)
	case BalancingHighestMTU:
		return b.bestHighestMTUConnection(snap)
	case BalancingLeastLoss:
		if !b.hasLossSignal(snap) {
			return b.roundRobinBestConnection(snap)
		}
		return b.bestScoredConnection(snap, b.lossScore)
	case BalancingLowestLatency:
		if !b.hasLatencySignal(snap) {
			return b.roundRobinBestConnection(snap)
		}
		return b.bestScoredConnection(snap, b.latencyScore)
	default:
		return b.roundRobinBestConnection(snap)
	}
}

func (b *Balancer) GetBestConnectionExcluding(excludeKey string) (Connection, bool) {
	snap := b.snapshot.Load()
	if snap == nil || len(snap.valid) == 0 {
		return Connection{}, false
	}

	switch b.strategy {
	case BalancingRandom, BalancingMTUWeighted:
		ordered := b.rotatedValidIndices(snap, 1)
		for _, idx := range ordered {
			conn, ok := derefConnection(snap.connections, idx)
			if !ok || conn.Key == excludeKey {
				continue
			}
			return conn, true
		}
		return Connection{}, false
	case BalancingHighestMTU:
		return b.bestHighestMTUConnectionExcluding(snap, excludeKey)
	case BalancingLeastLoss:
		if !b.hasLossSignal(snap) {
			return b.roundRobinBestConnectionExcluding(snap, excludeKey)
		}
		return b.bestScoredConnectionExcluding(snap, b.lossScore, excludeKey)
	case BalancingLowestLatency:
		if !b.hasLatencySignal(snap) {
			return b.roundRobinBestConnectionExcluding(snap, excludeKey)
		}
		return b.bestScoredConnectionExcluding(snap, b.latencyScore, excludeKey)
	default:
		return b.roundRobinBestConnectionExcluding(snap, excludeKey)
	}
}

func (b *Balancer) GetUniqueConnections(requiredCount int) []Connection {
	snap := b.snapshot.Load()
	if snap == nil {
		return nil
	}

	count := normalizeRequiredCount(len(snap.valid), requiredCount, 1)
	if count <= 0 {
		return nil
	}

	if count == 1 {
		best, ok := b.GetBestConnection()
		if !ok {
			return nil
		}
		return []Connection{best}
	}

	switch b.strategy {
	case BalancingRandom:
		return b.selectRandom(snap, count)
	case BalancingMTUWeighted:
		return b.selectRoundRobin(snap, count)
	case BalancingHighestMTU:
		return b.selectHighestMTU(snap, count)
	case BalancingLeastLoss:
		if !b.hasLossSignal(snap) {
			return b.selectRoundRobin(snap, count)
		}
		return b.selectLowestScore(snap, count, b.lossScore)
	case BalancingLowestLatency:
		if !b.hasLatencySignal(snap) {
			return b.selectRoundRobin(snap, count)
		}
		return b.selectLowestScore(snap, count, b.latencyScore)
	default:
		return b.selectRoundRobin(snap, count)
	}
}

func (b *Balancer) GetAllValidConnections() []Connection {
	snap := b.snapshot.Load()
	if snap == nil || len(snap.valid) == 0 {
		return nil
	}
	return snapshotConnections(snap.connections, snap.valid)
}

// AllValidConnectionsIncludingBackup returns a copy of every IsValid connection
// regardless of tier (primary and backup). Unlike GetAllValidConnections — which
// returns only the active selection set — this exposes the full surviving pool so
// the adaptive-MTU layer can re-derive the operating point over all resolvers
// that are still reachable.
func (b *Balancer) AllValidConnectionsIncludingBackup() []Connection {
	snap := b.snapshot.Load()
	if snap == nil {
		return nil
	}
	out := make([]Connection, 0, len(snap.connections))
	for _, conn := range snap.connections {
		if conn.IsValid {
			out = append(out, conn)
		}
	}
	return out
}

// ReclassifyBackups recomputes every connection's Backup flag from the predicate
// (true => backup/reserve) under the balancer lock and rebuilds the active
// selection set. It updates both the snapshot and the backing sources so the
// change is race-free with the health loop and visible to the rest of the client.
func (b *Balancer) ReclassifyBackups(isBackup func(Connection) bool) {
	if isBackup == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	snap := b.snapshot.Load()
	if snap == nil {
		return
	}
	connections := make([]Connection, len(snap.connections))
	copy(connections, snap.connections)
	for idx := range connections {
		if idx < len(b.sources) && b.sources[idx] != nil {
			connections[idx] = *b.sources[idx]
		}
		backup := connections[idx].IsValid && isBackup(connections[idx])
		connections[idx].Backup = backup
		if idx < len(b.sources) && b.sources[idx] != nil {
			b.sources[idx].Backup = backup
		}
	}

	b.snapshot.Store(&balancerSnapshot{
		version:     b.version.Add(1),
		connections: connections,
		valid:       rebuildValidIndices(connections),
		indexByKey:  snap.indexByKey,
		stats:       snap.stats,
	})
}

func (b *Balancer) AverageRTT(serverKey string) (time.Duration, bool) {
	stats := b.statsForKey(serverKey)
	if stats == nil {
		return 0, false
	}

	_, _, sum, count := stats.snapshot()
	if count == 0 {
		return 0, false
	}

	return time.Duration(sum/count) * time.Microsecond, true
}

// rebuildValidIndices returns the balancer's active selection set. Primary
// resolvers (valid and not Backup) are preferred; backup resolvers are included
// only when no primary is available, so the session normally runs entirely on
// the active pool but slow reserves still take over if every primary fails.
func rebuildValidIndices(connections []Connection) []int {
	primary := make([]int, 0, len(connections))
	var backup []int
	for idx := range connections {
		if !connections[idx].IsValid {
			continue
		}
		if connections[idx].Backup {
			backup = append(backup, idx)
		} else {
			primary = append(primary, idx)
		}
	}
	if len(primary) > 0 {
		return primary
	}
	return append(primary, backup...)
}

func (b *Balancer) statsForKey(serverKey string) *connectionStats {
	snap := b.snapshot.Load()
	if snap == nil {
		return nil
	}
	idx, ok := snap.indexByKey[serverKey]
	if !ok || idx < 0 || idx >= len(snap.stats) {
		return nil
	}
	return snap.stats[idx]
}

func normalizeRequiredCount(validCount, requiredCount, defaultIfInvalid int) int {
	if validCount <= 0 {
		return 0
	}

	if requiredCount <= 0 {
		requiredCount = defaultIfInvalid
	}

	if requiredCount > validCount {
		return validCount
	}

	return requiredCount
}

func (b *Balancer) selectRoundRobin(snap *balancerSnapshot, count int) []Connection {
	n := len(snap.valid)
	start := roundRobinStartIndex(b.rrCounter.Add(uint64(count))-uint64(count), n)
	selected := make([]Connection, count)
	for i := 0; i < count; i++ {
		conn, ok := derefConnection(snap.connections, snap.valid[(start+i)%n])
		if ok {
			selected[i] = conn
		}
	}
	return selected
}

func (b *Balancer) selectRandom(snap *balancerSnapshot, count int) []Connection {
	n := len(snap.valid)
	if count <= 0 || n == 0 {
		return nil
	}

	// Optimization for small count selection to avoid large allocations
	if count == 1 {
		idx := snap.valid[b.nextRandom()%uint64(n)]
		conn, ok := derefConnection(snap.connections, idx)
		if ok {
			return []Connection{conn}
		}
		return nil
	}

	indices := make([]int, n)
	copy(indices, snap.valid)

	for i := 0; i < count; i++ {
		j := i + int(b.nextRandom()%uint64(n-i))
		indices[i], indices[j] = indices[j], indices[i]
	}

	return snapshotConnections(snap.connections, indices[:count])
}

func (b *Balancer) selectLowestScore(snap *balancerSnapshot, count int, scorer func(*balancerSnapshot, int) uint64) []Connection {
	n := len(snap.valid)
	if count <= 0 || n == 0 {
		return nil
	}

	if count == 1 {
		conn, ok := b.bestScoredConnection(snap, scorer)
		if ok {
			return []Connection{conn}
		}
		return nil
	}

	type scoredIdx struct {
		idx   int
		score uint64
	}

	ordered := b.rotatedValidIndices(snap, count)
	scored := make([]scoredIdx, n)
	for i, idx := range ordered {
		scored[i] = scoredIdx{idx: idx, score: scorer(snap, idx)}
	}

	// Simple selection sort for small 'count'
	for i := 0; i < count && i < n; i++ {
		minIdx := i
		for j := i + 1; j < n; j++ {
			if scored[j].score < scored[minIdx].score {
				minIdx = j
			}
		}
		scored[i], scored[minIdx] = scored[minIdx], scored[i]
	}

	indices := make([]int, count)
	for i := 0; i < count; i++ {
		indices[i] = scored[i].idx
	}

	return snapshotConnections(snap.connections, indices)
}

func (b *Balancer) selectHighestMTU(snap *balancerSnapshot, count int) []Connection {
	if snap == nil || count <= 0 || len(snap.valid) == 0 {
		return nil
	}
	if count > len(snap.valid) {
		count = len(snap.valid)
	}
	selected := make([]int, 0, count)
	used := make(map[int]struct{}, count)
	for len(selected) < count {
		best := -1
		for _, idx := range snap.valid {
			if _, ok := used[idx]; ok {
				continue
			}
			if best == -1 || higherMTUFirst(snap.connections[idx], snap.connections[best]) {
				best = idx
			}
		}
		if best == -1 {
			break
		}
		used[best] = struct{}{}
		selected = append(selected, best)
	}
	return snapshotConnections(snap.connections, selected)
}

func (b *Balancer) bestHighestMTUConnection(snap *balancerSnapshot) (Connection, bool) {
	selected := b.selectHighestMTU(snap, 1)
	if len(selected) == 0 {
		return Connection{}, false
	}
	return selected[0], true
}

func (b *Balancer) bestHighestMTUConnectionExcluding(snap *balancerSnapshot, excludeKey string) (Connection, bool) {
	for _, conn := range b.selectHighestMTU(snap, len(snap.valid)) {
		if conn.Key != "" && conn.Key != excludeKey {
			return conn, true
		}
	}
	return Connection{}, false
}

func higherMTUFirst(a, b Connection) bool {
	if a.DownloadMTUBytes != b.DownloadMTUBytes {
		return a.DownloadMTUBytes > b.DownloadMTUBytes
	}
	if a.UploadMTUBytes != b.UploadMTUBytes {
		return a.UploadMTUBytes > b.UploadMTUBytes
	}
	if a.MTUResolveTime != b.MTUResolveTime {
		if a.MTUResolveTime <= 0 {
			return false
		}
		if b.MTUResolveTime <= 0 {
			return true
		}
		return a.MTUResolveTime < b.MTUResolveTime
	}
	return a.Key < b.Key
}

func snapshotConnections(connections []Connection, indices []int) []Connection {
	selected := make([]Connection, len(indices))
	for i, idx := range indices {
		if idx < 0 || idx >= len(connections) {
			continue
		}
		selected[i] = connections[idx]
	}
	return selected
}

func (b *Balancer) bestScoredConnection(snap *balancerSnapshot, scorer func(*balancerSnapshot, int) uint64) (Connection, bool) {
	ordered := b.rotatedValidIndices(snap, 1)
	bestIndex := -1
	var bestScore uint64
	for _, idx := range ordered {
		score := scorer(snap, idx)
		if bestIndex == -1 || score < bestScore {
			bestIndex = idx
			bestScore = score
		}
	}
	if bestIndex < 0 {
		return Connection{}, false
	}
	return derefConnection(snap.connections, bestIndex)
}

func (b *Balancer) bestScoredConnectionExcluding(snap *balancerSnapshot, scorer func(*balancerSnapshot, int) uint64, excludeKey string) (Connection, bool) {
	ordered := b.rotatedValidIndices(snap, 1)
	bestIndex := -1
	var bestScore uint64
	for _, idx := range ordered {
		conn, ok := derefConnection(snap.connections, idx)
		if !ok || conn.Key == excludeKey {
			continue
		}
		score := scorer(snap, idx)
		if bestIndex == -1 || score < bestScore {
			bestIndex = idx
			bestScore = score
		}
	}
	if bestIndex < 0 {
		return Connection{}, false
	}
	return derefConnection(snap.connections, bestIndex)
}

func derefConnection(connections []Connection, idx int) (Connection, bool) {
	if idx < 0 || idx >= len(connections) {
		return Connection{}, false
	}
	return connections[idx], true
}

func (b *Balancer) lossScore(snap *balancerSnapshot, idx int) uint64 {
	stats := statsByIndex(snap, idx)
	if stats == nil {
		return 500
	}
	sent, acked, _, _ := stats.snapshot()
	if sent < 5 {
		return 500
	}

	if acked >= sent {
		return 0
	}
	// loss ratio in per 1000 for integer math (a/b -> a*1000/b)
	return (sent - acked) * 1000 / sent
}

// AggregateLossPerMille returns the mean observed packet loss (parts per 1000)
// across valid connections that have enough samples, or 0 when there is no loss
// signal yet. It drives tier-1 adaptive duplication.
func (b *Balancer) AggregateLossPerMille() uint64 {
	snap := b.snapshot.Load()
	if snap == nil || len(snap.valid) == 0 {
		return 0
	}
	var total, n uint64
	for _, idx := range snap.valid {
		stats := statsByIndex(snap, idx)
		if stats == nil {
			continue
		}
		sent, acked, _, _ := stats.snapshot()
		if sent < 5 {
			continue
		}
		loss := uint64(0)
		if acked < sent {
			loss = (sent - acked) * 1000 / sent
		}
		total += loss
		n++
	}
	if n == 0 {
		return 0
	}
	return total / n
}

func (b *Balancer) latencyScore(snap *balancerSnapshot, idx int) uint64 {
	stats := statsByIndex(snap, idx)
	if stats == nil {
		return 999000
	}
	_, _, sum, count := stats.snapshot()
	if count < 5 {
		return 999000
	}
	return sum / count
}

// mtuGoodputWeight returns the selection weight for a resolver as its effective
// download *goodput* — the download MTU discounted by the fraction of packets it
// actually delivers at that MTU (1 - measured loss). Weighting by goodput instead
// of raw MTU makes transport selection robust against resolvers whose nominal MTU
// overstates what they can carry: a resolver that was assigned a high MTU but
// drops a large share of packets at it is automatically weighted down toward the
// throughput it can really sustain, rather than being over-favored for its size.
// Resolvers with an unknown (≤0) MTU get a unit weight so they stay reachable.
func mtuGoodputWeight(conn *Connection) uint64 {
	mtu := conn.DownloadMTUBytes
	if mtu <= 0 {
		return 1
	}
	loss := conn.DownloadMTULoss
	if loss < 0 {
		loss = 0
	}
	if loss > 1 {
		loss = 1
	}
	weight := uint64(float64(mtu)*(1.0-loss) + 0.5)
	if weight < 1 {
		// Even a near-fully-lossy resolver keeps a floor weight so it is not starved
		// entirely and can recover if its loss estimate improves.
		weight = 1
	}
	return weight
}

// weightedByMTUConnection picks an active-pool resolver with probability
// proportional to its effective download goodput (MTU × delivery rate). Falls
// back to round-robin when there is no usable weight signal.
func (b *Balancer) weightedByMTUConnection(snap *balancerSnapshot) (Connection, bool) {
	if snap == nil || len(snap.valid) == 0 {
		return Connection{}, false
	}
	total := uint64(0)
	for _, idx := range snap.valid {
		total += mtuGoodputWeight(&snap.connections[idx])
	}
	if total == 0 {
		return b.roundRobinBestConnection(snap)
	}

	r := b.nextRandom() % total
	for _, idx := range snap.valid {
		w := mtuGoodputWeight(&snap.connections[idx])
		if r < w {
			return derefConnection(snap.connections, idx)
		}
		r -= w
	}
	return derefConnection(snap.connections, snap.valid[len(snap.valid)-1])
}

func (b *Balancer) roundRobinBestConnection(snap *balancerSnapshot) (Connection, bool) {
	if snap == nil || len(snap.valid) == 0 {
		return Connection{}, false
	}
	pos := roundRobinStartIndex(b.rrCounter.Add(1)-1, len(snap.valid))
	return derefConnection(snap.connections, snap.valid[pos])
}

func (b *Balancer) roundRobinBestConnectionExcluding(snap *balancerSnapshot, excludeKey string) (Connection, bool) {
	if snap == nil || len(snap.valid) == 0 {
		return Connection{}, false
	}
	ordered := b.rotatedValidIndices(snap, 1)
	for _, idx := range ordered {
		conn, ok := derefConnection(snap.connections, idx)
		if !ok || conn.Key == excludeKey {
			continue
		}
		return conn, true
	}
	return Connection{}, false
}

func (b *Balancer) rotatedValidIndices(snap *balancerSnapshot, step int) []int {
	if snap == nil || len(snap.valid) == 0 {
		return nil
	}
	if step < 1 {
		step = 1
	}

	start := roundRobinStartIndex(b.rrCounter.Add(uint64(step))-uint64(step), len(snap.valid))
	ordered := make([]int, len(snap.valid))
	for i := range snap.valid {
		ordered[i] = snap.valid[(start+i)%len(snap.valid)]
	}
	return ordered
}

func roundRobinStartIndex(counter uint64, n int) int {
	if n <= 0 {
		return 0
	}
	return int(counter % uint64(n))
}

func (b *Balancer) hasLossSignal(snap *balancerSnapshot) bool {
	if snap == nil {
		return false
	}
	for _, idx := range snap.valid {
		stats := statsByIndex(snap, idx)
		if stats == nil {
			continue
		}
		sent, _, _, _ := stats.snapshot()
		if sent >= 5 {
			return true
		}
	}
	return false
}

func (b *Balancer) hasLatencySignal(snap *balancerSnapshot) bool {
	if snap == nil {
		return false
	}
	for _, idx := range snap.valid {
		stats := statsByIndex(snap, idx)
		if stats == nil {
			continue
		}
		_, _, _, count := stats.snapshot()
		if count >= 5 {
			return true
		}
	}
	return false
}

func statsByIndex(snap *balancerSnapshot, idx int) *connectionStats {
	if snap == nil || idx < 0 || idx >= len(snap.stats) {
		return nil
	}
	return snap.stats[idx]
}

func (s *connectionStats) snapshot() (sent uint64, acked uint64, rttMicrosSum uint64, rttCount uint64) {
	if s == nil {
		return 0, 0, 0, 0
	}

	s.mu.RLock()
	sent = s.sent
	acked = s.acked
	rttMicrosSum = s.rttMicrosSum
	rttCount = s.rttCount
	s.mu.RUnlock()
	return sent, acked, rttMicrosSum, rttCount
}

func (s *connectionStats) applyHalfLifeLocked() {
	if s == nil {
		return
	}
	if s.sent <= connectionStatsHalfLifeThreshold &&
		s.acked <= connectionStatsHalfLifeThreshold &&
		s.rttCount <= connectionStatsHalfLifeThreshold {
		return
	}

	s.sent /= 2
	s.acked /= 2
	s.rttMicrosSum /= 2
	s.rttCount /= 2
}

func (b *Balancer) nextRandom() uint64 {
	for {
		current := b.rngState.Load()
		next := xorshift64(current)
		if b.rngState.CompareAndSwap(current, next) {
			return next
		}
	}
}

func seedRNG() uint64 {
	seed := uint64(time.Now().UnixNano())
	if seed == 0 {
		return 0x9e3779b97f4a7c15
	}
	return seed
}

func xorshift64(v uint64) uint64 {
	if v == 0 {
		v = 0x9e3779b97f4a7c15
	}
	v ^= v << 13
	v ^= v >> 7
	v ^= v << 17
	return v
}
