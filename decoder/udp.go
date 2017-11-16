package decoder

import (
	"github.com/google/gopacket/layers"
)

type UDP struct {
	SrcPort  layers.UDPPort `json:"sport"`
	DstPort  layers.UDPPort `json:"dport"`
	Length   uint16         `json:"-"`
	Checksum uint16         `json:"-"`
	Payload  []byte         `json:"payload"`
}

func NewUDP(udp *layers.UDP) (u *UDP, pktType PktType) {
	pktType = PktTypeUDP
	u = &UDP{}
	u.SrcPort = udp.SrcPort
	u.DstPort = udp.DstPort
	u.Checksum = udp.Checksum
	u.Payload = udp.Payload
	return u, pktType
}
