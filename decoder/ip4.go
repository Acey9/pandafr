package decoder

import (
	"github.com/google/gopacket/layers"
	"net"
)

type IPv4 struct {
	Version    uint8               `json:"version"`
	IHL        uint8               `json:"_"`
	TOS        uint8               `json:"_"`
	Length     uint16              `json:"_"`
	Id         uint16              `json:"_"`
	Flags      layers.IPv4Flag     `json:"_"`
	FragOffset uint16              `json:"_"`
	TTL        uint8               `json:"_"`
	Protocol   layers.IPProtocol   `json:"proto"`
	Checksum   uint16              `json:"_"`
	SrcIP      net.IP              `json:"sip"`
	DstIP      net.IP              `json:"dip"`
	Options    []layers.IPv4Option `json:"-"`
	Padding    []byte              `json:"_"`
}

func NewIP4(ip *layers.IPv4) *IPv4 {
	i := &IPv4{}
	i.Version = ip.Version
	i.IHL = ip.IHL
	i.TOS = ip.TOS
	i.Length = ip.Length
	i.Id = ip.Id
	i.Flags = ip.Flags
	i.FragOffset = ip.FragOffset
	i.TTL = ip.TTL
	i.Protocol = ip.Protocol
	i.Checksum = ip.Checksum
	i.SrcIP = ip.SrcIP
	i.DstIP = ip.DstIP
	i.Options = ip.Options
	i.Padding = ip.Padding
	return i
}
