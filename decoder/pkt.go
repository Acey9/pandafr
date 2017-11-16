package decoder

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"time"
)

type Packet struct {
	Ts          time.Time `json:"ts"`
	PktType     PktType   `json:"-"`
	Ptype       string    `json:"ptype,omitempty"`
	IPv         uint8     `json:"ipv"`
	Ip4         *IPv4     `json:"ip4,omitempty"`
	Ip6         *IPv6     `json:"ip6,omitempty"`
	Tcp         *TCP      `json:"tcp,omitempty"`
	Udp         *UDP      `json:"udp,omitempty"`
	Dns         *DNS      `json:"dns,omitempty"`
	PayloadSha1 string    `json:"psha1,omitempty"`
}

const (
	PktTypeTCP PktType = 1
	PktTypeUDP PktType = 2
	PktTypeDNS PktType = 3
)

func (pkt *Packet) Compress(source []byte) bytes.Buffer {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	w.Write(source)
	w.Close()
	return buf
}

func (pkt *Packet) Sha1HexDigest(str string) string {
	h := sha1.New()
	io.WriteString(h, str)
	return hex.EncodeToString(h.Sum(nil))
}

type PktType uint8

func (pt PktType) String() string {
	var typeStr string
	switch pt {
	case PktTypeTCP:
		typeStr = "tcp"
	case PktTypeUDP:
		typeStr = "udp"
	case PktTypeDNS:
		typeStr = "dns"
	}
	return typeStr
}
