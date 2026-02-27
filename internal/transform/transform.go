package transform

import (
	"bytes"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/captainpacket/tenableio-sc-proxy/internal/forwardsc"
	"github.com/captainpacket/tenableio-sc-proxy/internal/tenableio"
)

type Options struct {
	DedupeByIP bool
}

type Stats struct {
	InputRows               int
	OutputRows              int
	DroppedInvalidIP        int
	DroppedNegativeSeverity int
	DuplicatesMerged        int
}

func ToSumipRows(in []tenableio.HostAggregate) []forwardsc.SumipHost {
	rows, _ := ToSumipRowsWithStats(in, Options{})
	return rows
}

func ToSumipRowsWithStats(in []tenableio.HostAggregate, opts Options) ([]forwardsc.SumipHost, Stats) {
	stats := Stats{
		InputRows: len(in),
	}

	out := make([]forwardsc.SumipHost, 0, len(in))
	byIP := map[string]int{}
	for _, row := range in {
		ip := strings.TrimSpace(row.IP)
		if net.ParseIP(ip) == nil {
			stats.DroppedInvalidIP++
			continue
		}
		if row.Medium < 0 || row.High < 0 || row.Critical < 0 {
			stats.DroppedNegativeSeverity++
			continue
		}

		score := row.Score
		if score == nil {
			fallback := row.Critical*40 + row.High*10 + row.Medium*3
			score = &fallback
		}
		if score == nil {
			continue
		}

		candidate := forwardsc.SumipHost{
			IP:               ip,
			DNSName:          row.DNSName,
			MACAddress:       row.MACAddress,
			Score:            strconv.Itoa(*score),
			SeverityMedium:   strconv.Itoa(row.Medium),
			SeverityHigh:     strconv.Itoa(row.High),
			SeverityCritical: strconv.Itoa(row.Critical),
		}

		if !opts.DedupeByIP {
			out = append(out, candidate)
			continue
		}

		if idx, ok := byIP[candidate.IP]; ok {
			stats.DuplicatesMerged++
			merged := mergeRows(out[idx], candidate)
			out[idx] = merged
			continue
		}
		byIP[candidate.IP] = len(out)
		out = append(out, candidate)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].IP == out[j].IP {
			if out[i].DNSName == out[j].DNSName {
				return out[i].MACAddress < out[j].MACAddress
			}
			return out[i].DNSName < out[j].DNSName
		}
		return bytesCompareIP(out[i].IP, out[j].IP) < 0
	})

	stats.OutputRows = len(out)
	return out, stats
}

func mergeRows(existing, incoming forwardsc.SumipHost) forwardsc.SumipHost {
	if strings.TrimSpace(existing.DNSName) == "" {
		existing.DNSName = incoming.DNSName
	}
	if strings.TrimSpace(existing.MACAddress) == "" {
		existing.MACAddress = incoming.MACAddress
	}

	existing.Score = strconv.Itoa(maxInt(parseInt(existing.Score), parseInt(incoming.Score)))
	existing.SeverityMedium = strconv.Itoa(maxInt(parseInt(existing.SeverityMedium), parseInt(incoming.SeverityMedium)))
	existing.SeverityHigh = strconv.Itoa(maxInt(parseInt(existing.SeverityHigh), parseInt(incoming.SeverityHigh)))
	existing.SeverityCritical = strconv.Itoa(maxInt(parseInt(existing.SeverityCritical), parseInt(incoming.SeverityCritical)))
	return existing
}

func parseInt(v string) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0
	}
	return n
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func bytesCompareIP(a, b string) int {
	ipa := net.ParseIP(a)
	ipb := net.ParseIP(b)
	if ipa == nil && ipb == nil {
		return 0
	}
	if ipa == nil {
		return -1
	}
	if ipb == nil {
		return 1
	}
	ab := ipa.To16()
	bb := ipb.To16()
	for i := 0; i < len(ab) && i < len(bb); i++ {
		if ab[i] != bb[i] {
			if ab[i] < bb[i] {
				return -1
			}
			return 1
		}
	}
	return bytes.Compare(ab, bb)
}
