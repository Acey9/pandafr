package decoder

import (
	"github.com/google/gopacket/layers"
	"net"
)

type DNS struct {
	// Header fields
	ID     uint16           `json:"_"`
	QR     bool             `json:"_"`
	OpCode layers.DNSOpCode `json:"_"`

	AA bool  `json:"-"` // Authoritative answer
	TC bool  `json:"-"` // Truncated
	RD bool  `json:"-"` // Recursion desired
	RA bool  `json:"-"` // Recursion available
	Z  uint8 `json:"-"` // Resrved for future use

	ResponseCode layers.DNSResponseCode `json:"rescode"`
	QDCount      uint16                 `json:"-"` // Number of questions to expect
	ANCount      uint16                 `json:"-"` // Number of answers to expect
	NSCount      uint16                 `json:"-"` // Number of authorities to expect
	ARCount      uint16                 `json:"-"` // Number of additional records to expect

	// Entries
	Questions []DNSQuestion       `json:"questions,omitempty"`
	Answers   []DNSResourceRecord `json:"answers,omitempty"`
}

type DNSQuestion struct {
	Name  string          `json:"name"`
	Type  layers.DNSType  `json:"type"`
	Class layers.DNSClass `json:"class"`
}

type DNSResourceRecord struct {
	// Header
	Name  string          `json:"name"`
	Type  layers.DNSType  `json:"type"`
	Class layers.DNSClass `json:"class"`
	TTL   uint32          `json:"ttl"`

	// RDATA Decoded Values
	IP    net.IP `json:"ip,omitempty"`
	NS    string `json:"ns,omitempty"`
	CNAME string `json:"cname,omitempty"`
}

func NewDNS(dns *layers.DNS) (d *DNS, pktType PktType) {
	d = &DNS{}

	d.ID = dns.ID
	d.QR = dns.QR
	d.OpCode = dns.OpCode

	d.AA = dns.AA
	d.TC = dns.TC
	d.RD = dns.RD
	d.RA = dns.RA
	d.Z = dns.Z

	d.ResponseCode = dns.ResponseCode
	d.QDCount = dns.QDCount
	d.ANCount = dns.ANCount
	d.NSCount = dns.NSCount
	d.ARCount = dns.ARCount

	for _, q := range dns.Questions {
		qs := DNSQuestion{}
		qs.Name = string(q.Name)
		qs.Type = q.Type
		qs.Class = q.Class
		d.Questions = append(d.Questions, qs)
	}

	for _, r := range dns.Answers {
		res := DNSResourceRecord{}
		res.Name = string(r.Name)
		res.Type = r.Type
		res.Class = r.Class
		res.TTL = r.TTL

		res.IP = r.IP
		res.NS = string(r.NS)
		res.CNAME = string(r.CNAME)

		d.Answers = append(d.Answers, res)
	}
	pktType = PktTypeDNS
	return d, pktType
}
