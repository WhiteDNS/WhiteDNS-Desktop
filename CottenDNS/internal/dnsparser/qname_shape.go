// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// qname_shape.go — QNAME reshaping. The encoded tunnel payload is laid into the
// query name as DNS labels. The classic DNS-tunnel fingerprint is a single chain
// of uniformly-maximum-length (63-char) labels under one domain. This file makes
// the per-label lengths configurable and jittered so the query name looks more
// like ordinary multi-label subdomains.
//
// SAFETY — why this can never desync client and server: the receiver recovers the
// payload by concatenating ALL labels and stripping the dots (see the server's
// stripLabelDots and the client's CNAME/A decoders). The label *boundaries* are
// therefore irrelevant to decoding — only the concatenated bytes matter. So the
// sender may split the payload into labels of any lengths it likes with no change
// on the receiver. The only invariant that must hold is the client's own capacity
// math (CalculateMaxEncodedQNameChars / encodedQNameLen) agreeing with how many
// labels the builder actually emits — both go through qnameLabelCount here.
// ==============================================================================

package dnsparser

import "sync/atomic"

// qnameLabelLength is the target maximum label length used when splitting the
// encoded payload into QNAME labels. The DNS hard limit is 63 (maxDNSLabelLen);
// a smaller value yields shorter, more numerous labels. Process-global and set
// once at startup via SetQNameLabelLength; the server leaves it at the default.
var qnameLabelLength atomic.Int32

func init() { qnameLabelLength.Store(maxDNSLabelLen) }

// SetQNameLabelLength configures the target QNAME label length. Values outside
// 1..63 (including 0/unset) select the default of 63 (the DNS maximum), so an
// unconfigured client keeps the legacy maximal-label behavior. Call once before
// any tunnel queries are built.
func SetQNameLabelLength(n int) {
	if n < 1 || n > maxDNSLabelLen {
		n = maxDNSLabelLen
	}
	qnameLabelLength.Store(int32(n))
}

func qnameLabelLen() int {
	v := int(qnameLabelLength.Load())
	if v < 1 || v > maxDNSLabelLen {
		return maxDNSLabelLen
	}
	return v
}

// qnameLabelCount is how many labels an encoded payload of the given length is
// split into under the current shaping. This is the single source of truth shared
// by the wire builder and the capacity calculations, so a name can never exceed
// the 253-byte limit.
func qnameLabelCount(encodedLen int) int {
	if encodedLen <= 0 {
		return 0
	}
	l := qnameLabelLen()
	return (encodedLen + l - 1) / l
}

// shapeQNameLabelLengths returns per-label byte lengths for splitting an encoded
// payload of encodedLen bytes into exactly qnameLabelCount(encodedLen) labels,
// each in [1, 63] and summing to encodedLen, with a seeded jitter so the labels
// are not all uniform. The seed only affects the (decode-irrelevant) split
// positions, never the concatenated payload.
func shapeQNameLabelLengths(encodedLen int, seed uint64) []int {
	count := qnameLabelCount(encodedLen)
	if count <= 0 {
		return nil
	}

	// Default (max label length): legacy greedy split — fewest, longest labels.
	// This keeps the wire bytes identical to the historical builder so the
	// default behavior is unchanged; reshaping is opt-in via a smaller length.
	if qnameLabelLen() >= maxDNSLabelLen {
		lengths := make([]int, count)
		remaining := encodedLen
		for i := range lengths {
			if remaining > maxDNSLabelLen {
				lengths[i] = maxDNSLabelLen
				remaining -= maxDNSLabelLen
			} else {
				lengths[i] = remaining
				remaining = 0
			}
		}
		return lengths
	}

	lengths := make([]int, count)
	base := encodedLen / count
	rem := encodedLen % count
	for i := range lengths {
		lengths[i] = base
		if i < rem {
			lengths[i]++
		}
	}

	// Move a seeded amount between adjacent pairs, preserving the sum and the
	// [1, 63] bounds on each label.
	s := seed | 1
	for i := 0; i+1 < count; i += 2 {
		s = s*6364136223846793005 + 1442695040888963407 // LCG step
		up := min(lengths[i]-1, maxDNSLabelLen-lengths[i+1])
		down := min(lengths[i+1]-1, maxDNSLabelLen-lengths[i])
		span := up + down
		if span <= 0 {
			continue
		}
		delta := int(s>>33)%(span+1) - down // in [-down, up]
		lengths[i] -= delta
		lengths[i+1] += delta
	}
	return lengths
}
