package decoder

import (
	"github.com/google/gopacket/layers"
	"net"
)

type IPv6 struct {
	Version      uint8                `json:"version"`
	TrafficClass uint8                `json:"-"`
	FlowLabel    uint32               `json:"-"`
	Length       uint16               `json:"-"`
	NextHeader   layers.IPProtocol    `json:"proto"`
	HopLimit     uint8                `json:"-"`
	SrcIP        net.IP               `json:"sip"`
	DstIP        net.IP               `json:"dip"`
	HopByHop     *layers.IPv6HopByHop `json:"-"`
}

func NewIP6(ip6 *layers.IPv6) *IPv6 {
	i := &IPv6{}
	i.Version = ip6.Version
	i.TrafficClass = ip6.TrafficClass
	i.FlowLabel = ip6.FlowLabel
	i.Length = ip6.Length
	i.NextHeader = ip6.NextHeader
	i.HopLimit = ip6.HopLimit
	i.SrcIP = ip6.SrcIP
	i.DstIP = ip6.DstIP
	i.HopByHop = ip6.HopByHop
	return i
}
