package wire

import "fmt"

// packAPLib writes the raw aPLib token stream consumed by the embedded
// aP_depack routine. This encoder is locally written and uses a bounded
// greedy match finder; it does not copy a third-party packer implementation.
func packAPLib(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("cannot pack an empty module")
	}
	p := apBitWriter{data: make([]byte, 0, len(input)+len(input)/8+8), bitIndex: -1}
	p.data = append(p.data, input[0]) // The first byte is always a literal.
	last := make(map[uint32]int, min(len(input), 1<<16))
	lastPair := make(map[uint16]int, min(len(input), 1<<16))
	previousMatch := false
	for at := 1; at < len(input); {
		bestLen, bestOff := 0, 0
		if at+3 <= len(input) {
			key := apTriple(input, at)
			if prior, ok := last[key]; ok {
				off := at - prior
				if off > 0 && off <= 0xffff {
					limit := min(len(input)-at, 1<<20)
					for bestLen < limit && input[at+bestLen] == input[at+bestLen-off] {
						bestLen++
					}
					bestOff = off
				}
			}
		}
		// A long match's gamma length must be at least two. The format adds
		// two output bytes for offsets below 128, and one or two for larger
		// offsets. Requiring four bytes is always representable and profitable.
		if bestLen >= 4 {
			p.bit(1)
			p.bit(0)
			gammaOff := uint32(bestOff>>8) + 2
			if !previousMatch {
				gammaOff++
			}
			p.gamma(gammaOff)
			p.data = append(p.data, byte(bestOff))
			bonus := 0
			if bestOff >= 32000 {
				bonus++
			}
			if bestOff >= 1280 {
				bonus++
			}
			if bestOff < 128 {
				bonus += 2
			}
			p.gamma(uint32(bestLen - bonus))
			for i := 0; i < bestLen; i++ {
				if at+i+3 <= len(input) {
					last[apTriple(input, at+i)] = at + i
				}
				if at+i+2 <= len(input) {
					lastPair[apPair(input, at+i)] = at + i
				}
			}
			at += bestLen
			previousMatch = true
			continue
		}
		// The short form is smaller for nearby two- and three-byte matches.
		shortLen, shortOff := 0, 0
		if at+2 <= len(input) {
			if prior, ok := lastPair[apPair(input, at)]; ok && at-prior <= 127 {
				shortOff = at - prior
				shortLen = 2
				if at+2 < len(input) && input[at+2] == input[at+2-shortOff] {
					shortLen = 3
				}
			}
		}
		if shortLen >= 2 {
			p.bit(1)
			p.bit(1)
			p.bit(0)
			p.data = append(p.data, byte((shortOff<<1)|(shortLen-2)))
			for i := 0; i < shortLen; i++ {
				if at+i+3 <= len(input) {
					last[apTriple(input, at+i)] = at + i
				}
				if at+i+2 <= len(input) {
					lastPair[apPair(input, at+i)] = at + i
				}
			}
			at += shortLen
			previousMatch = true
			continue
		}
		if input[at] == 0 {
			p.bit(1)
			p.bit(1)
			p.bit(1)
			for i := 0; i < 4; i++ {
				p.bit(0)
			}
		} else {
			p.bit(0)
			p.data = append(p.data, input[at])
		}
		if at+3 <= len(input) {
			last[apTriple(input, at)] = at
		}
		if at+2 <= len(input) {
			lastPair[apPair(input, at)] = at
		}
		at++
		previousMatch = false
	}
	// 110 followed by a zero offset is the end marker.
	p.bit(1)
	p.bit(1)
	p.bit(0)
	p.data = append(p.data, 0)
	return p.data, nil
}

func apTriple(input []byte, at int) uint32 {
	return uint32(input[at])<<16 | uint32(input[at+1])<<8 | uint32(input[at+2])
}

func apPair(input []byte, at int) uint16 {
	return uint16(input[at])<<8 | uint16(input[at+1])
}

type apBitWriter struct {
	data     []byte
	bitIndex int
	used     uint8
}

func (p *apBitWriter) bit(value uint8) {
	if p.bitIndex < 0 || p.used == 8 {
		p.bitIndex = len(p.data)
		p.data = append(p.data, 0)
		p.used = 0
	}
	if value != 0 {
		p.data[p.bitIndex] |= 1 << (7 - p.used)
	}
	p.used++
}

func (p *apBitWriter) gamma(value uint32) {
	// Gamma2 encodes values >= 2 as data/continuation bit pairs.
	for bit := uint32(1) << (31 - uint32LeadingZeros(value)); bit > 1; {
		bit >>= 1
		if value&bit != 0 {
			p.bit(1)
		} else {
			p.bit(0)
		}
		if bit > 1 {
			p.bit(1)
		} else {
			p.bit(0)
		}
	}
}

func uint32LeadingZeros(value uint32) uint32 {
	var zeros uint32
	for bit := uint32(1) << 31; bit != 0 && value&bit == 0; bit >>= 1 {
		zeros++
	}
	return zeros
}
