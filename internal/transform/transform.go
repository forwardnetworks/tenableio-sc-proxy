package transform

import (
	"bytes"
	"net"
	"sort"
	"strconv"

	"github.com/captainpacket/tenableio-sc-proxy/internal/forwardsc"
	"github.com/captainpacket/tenableio-sc-proxy/internal/tenableio"
)

func ToSumipRows(in []tenableio.HostAggregate) []forwardsc.SumipHost {
	out := make([]forwardsc.SumipHost, 0, len(in))
	for _, row := range in {
		if net.ParseIP(row.IP) == nil {
			continue
		}
		if row.Medium < 0 || row.High < 0 || row.Critical < 0 {
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

		out = append(out, forwardsc.SumipHost{
			IP:               row.IP,
			DNSName:          row.DNSName,
			MACAddress:       row.MACAddress,
			Score:            strconv.Itoa(*score),
			SeverityMedium:   strconv.Itoa(row.Medium),
			SeverityHigh:     strconv.Itoa(row.High),
			SeverityCritical: strconv.Itoa(row.Critical),
		})
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

	return out
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
