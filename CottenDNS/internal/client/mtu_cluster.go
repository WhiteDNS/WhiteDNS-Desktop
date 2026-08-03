// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// mtu_cluster.go — Layer 2 of the adaptive per-group MTU strategy: cluster the
// valid resolvers into groups that share a similar viable MTU range, so a future
// Layer 3 can run each group at the largest MTU it can sustain instead of
// forcing the global minimum on everyone.
//
// Clustering is 1-D gap-based banding over each resolver's viable *download* MTU
// (the session-limiting, server-driven direction): the valid connections are
// sorted by download MTU and a new group is cut wherever the gap between two
// consecutive values exceeds gapRatio of the larger value. Each group's applied
// MTU is the minimum within the group, so every member can sustain it.
//
// This is intentionally read-only today: clusterConnectionsByMTU is a pure
// function and the result is logged/stored but does not yet drive routing.
// ==============================================================================

package client

import "sort"

// mtuGroup is a cluster of resolver connections that share a similar viable MTU
// range. UploadMTU/DownloadMTU are the safe (minimum) values across the group's
// members, so every member can carry them.
type mtuGroup struct {
	UploadMTU   int
	DownloadMTU int
	Members     []Connection
}

// clusterConnectionsByMTU groups valid connections into MTU bands. It considers
// only connections with IsValid set and a positive download MTU. The returned
// groups are sorted by DownloadMTU descending (largest-capacity group first).
// The input slice is not mutated.
//
// gapRatio is the relative gap (0..1) that starts a new band: a new group begins
// when (next-prev) > gapRatio*next over the ascending-sorted download MTUs. A
// non-positive gapRatio falls back to 0.25.
func clusterConnectionsByMTU(conns []Connection, gapRatio float64) []mtuGroup {
	if gapRatio <= 0 {
		gapRatio = 0.25
	}

	valid := make([]Connection, 0, len(conns))
	for _, conn := range conns {
		if conn.IsValid && conn.DownloadMTUBytes > 0 {
			valid = append(valid, conn)
		}
	}
	if len(valid) == 0 {
		return nil
	}

	sort.SliceStable(valid, func(i, j int) bool {
		return valid[i].DownloadMTUBytes < valid[j].DownloadMTUBytes
	})

	var groups []mtuGroup
	current := []Connection{valid[0]}
	for i := 1; i < len(valid); i++ {
		prev := valid[i-1].DownloadMTUBytes
		next := valid[i].DownloadMTUBytes
		gap := next - prev
		if float64(gap) > gapRatio*float64(next) {
			groups = append(groups, buildMTUGroup(current))
			current = []Connection{valid[i]}
			continue
		}
		current = append(current, valid[i])
	}
	groups = append(groups, buildMTUGroup(current))

	// Largest-capacity group first.
	sort.SliceStable(groups, func(i, j int) bool {
		return groups[i].DownloadMTU > groups[j].DownloadMTU
	})
	return groups
}

// selectMTUOperatingPoint chooses the throughput-optimal session MTU over the
// valid connections (Layer 3, "best-group" strategy). It jointly optimizes both
// directions: for each resolver's own (upload, download) pair taken as a
// candidate floor (Uc, Dc), it forms the pool of resolvers that sustain BOTH
// (upload ≥ Uc and download ≥ Dc) and scores it as (U + D) × len(pool), where
// (U, D) are the safe minimums within that pool. The winning point balances
// per-packet size against resolver count in both directions, so a few slow
// resolvers — whether slow on upload or download — cannot throttle the session,
// and a single fast outlier cannot strand the crowd. Returns the chosen
// upload/download MTU and the pool size, or zeros when there is nothing to pick.
func selectMTUOperatingPoint(conns []Connection) (uploadMTU, downloadMTU, poolSize int) {
	type cand struct{ upload, download int }
	cands := make([]cand, 0, len(conns))
	for _, c := range conns {
		if c.IsValid && c.DownloadMTUBytes > 0 && c.UploadMTUBytes > 0 {
			cands = append(cands, cand{c.UploadMTUBytes, c.DownloadMTUBytes})
		}
	}
	if len(cands) == 0 {
		return 0, 0, 0
	}

	bestScore := -1
	for _, floor := range cands {
		pool := 0
		minUpload, minDownload := 0, 0
		for _, c := range cands {
			if c.upload < floor.upload || c.download < floor.download {
				continue
			}
			pool++
			if minUpload == 0 || c.upload < minUpload {
				minUpload = c.upload
			}
			if minDownload == 0 || c.download < minDownload {
				minDownload = c.download
			}
		}
		if pool == 0 {
			continue
		}
		score := (minUpload + minDownload) * pool
		// Prefer higher score; tie-break toward the larger download MTU.
		if score > bestScore || (score == bestScore && minDownload > downloadMTU) {
			bestScore = score
			uploadMTU = minUpload
			downloadMTU = minDownload
			poolSize = pool
		}
	}
	return uploadMTU, downloadMTU, poolSize
}

// selectMTUOperatingPointPreferHigh chooses the highest-MTU operating point the
// resolver fleet can sustain while keeping at least minPool resolvers in the
// active tier for redundancy. It is the selection policy for MTU-weighted
// balancing: rather than dragging every resolver down to the throughput-optimal
// common denominator, it lets the session run at the largest MTU a viable subset
// supports, so resolvers that can carry a higher MTU actually do. Resolvers below
// the chosen point are demoted to the backup tier by the caller.
//
// Among all per-resolver (upload, download) candidates whose sustaining pool has
// at least minPool members, it picks the largest download MTU (tie-break: larger
// upload, then larger pool). If no candidate reaches minPool (e.g. a tiny fleet),
// it falls back to the throughput-optimal point so a single fast outlier can
// never strand the session. minPool < 1 is treated as 1.
func selectMTUOperatingPointPreferHigh(conns []Connection, minPool int) (uploadMTU, downloadMTU, poolSize int) {
	if minPool < 1 {
		minPool = 1
	}
	type cand struct{ upload, download int }
	cands := make([]cand, 0, len(conns))
	for _, c := range conns {
		if c.IsValid && c.DownloadMTUBytes > 0 && c.UploadMTUBytes > 0 {
			cands = append(cands, cand{c.UploadMTUBytes, c.DownloadMTUBytes})
		}
	}
	if len(cands) == 0 {
		return 0, 0, 0
	}

	for _, floor := range cands {
		pool := 0
		minUpload, minDownload := 0, 0
		for _, c := range cands {
			if c.upload < floor.upload || c.download < floor.download {
				continue
			}
			pool++
			if minUpload == 0 || c.upload < minUpload {
				minUpload = c.upload
			}
			if minDownload == 0 || c.download < minDownload {
				minDownload = c.download
			}
		}
		if pool < minPool {
			continue
		}
		// Prefer the highest download MTU; tie-break toward larger upload, then a
		// larger pool for extra redundancy at the same MTU.
		better := minDownload > downloadMTU ||
			(minDownload == downloadMTU && minUpload > uploadMTU) ||
			(minDownload == downloadMTU && minUpload == uploadMTU && pool > poolSize)
		if better {
			uploadMTU = minUpload
			downloadMTU = minDownload
			poolSize = pool
		}
	}

	if downloadMTU == 0 {
		// Fleet too small to satisfy minPool at any raised MTU — do not strand it on
		// a lone fast resolver; use the throughput-optimal point instead.
		return selectMTUOperatingPoint(conns)
	}
	return uploadMTU, downloadMTU, poolSize
}

// buildMTUGroup computes a group's safe (minimum) upload/download MTU across its
// members. Upload MTU ignores members reporting 0 (upload not measured), but
// falls back to the minimum seen so the value is never larger than any member.
func buildMTUGroup(members []Connection) mtuGroup {
	g := mtuGroup{Members: members}
	for i, m := range members {
		if i == 0 || m.DownloadMTUBytes < g.DownloadMTU {
			g.DownloadMTU = m.DownloadMTUBytes
		}
		if m.UploadMTUBytes > 0 {
			if g.UploadMTU == 0 || m.UploadMTUBytes < g.UploadMTU {
				g.UploadMTU = m.UploadMTUBytes
			}
		}
	}
	return g
}
