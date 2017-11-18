package decoder

import (
	"github.com/google/gopacket/layers"
)

type TCP struct {
	SrcPort    layers.TCPPort     `json:"sport"`
	DstPort    layers.TCPPort     `json:"dport"`
	Seq        uint32             `json:"seq"`
	Ack        uint32             `json:"ack"`
	DataOffset uint8              `json:"-"`
	FIN        bool               `json:"-"`
	SYN        bool               `json:"-"`
	RST        bool               `json:"-"`
	PSH        bool               `json:"-"`
	ACK        bool               `json:"-"`
	URG        bool               `json:"-"`
	ECE        bool               `json:"-"`
	CWR        bool               `json:"-"`
	NS         bool               `json:"-"`
	Window     uint16             `json:"-"`
	Checksum   uint16             `json:"-"`
	Urgent     uint16             `json:"-"`
	Options    []layers.TCPOption `json:"-"`
	Padding    []byte             `json:"-"`
	Payload    []byte             `json:"payload"`
}

func NewTCP(tcp *layers.TCP) (t *TCP, pktType PktType) {
	pktType = PktTypeTCP
	t = &TCP{}
	t.SrcPort = tcp.SrcPort
	t.DstPort = tcp.DstPort
	t.Seq = tcp.Seq
	t.Ack = tcp.Ack
	t.DataOffset = tcp.DataOffset
	t.FIN = tcp.FIN
	t.SYN = tcp.SYN
	t.RST = tcp.RST
	t.PSH = tcp.PSH
	t.ACK = tcp.ACK
	t.URG = tcp.URG
	t.ECE = tcp.ECE
	t.CWR = tcp.CWR
	t.NS = tcp.NS
	t.Window = tcp.Window
	t.Checksum = tcp.Checksum
	t.Urgent = tcp.Urgent
	t.Options = tcp.Options
	t.Padding = tcp.Padding
	t.Payload = tcp.Payload
	return t, pktType
}
