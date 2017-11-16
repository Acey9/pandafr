package decoder

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Decoder struct {
}

func (decoder *Decoder) Process(data []byte, ci *gopacket.CaptureInfo) (pkt *Packet, err error) {
	pkt = &Packet{
		Ts: ci.Timestamp,
	}

	defer func() {
		pkt.Ptype = pkt.PktType.String()
	}()

	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
	for _, layer := range packet.Layers() {
		switch layer.LayerType() {
		case layers.LayerTypeIPv4:
			ip4l := packet.Layer(layers.LayerTypeIPv4)
			ip4, ok := ip4l.(*layers.IPv4)
			if !ok {
				return nil, nil
			}
			pkt.Ip4 = NewIP4(ip4)
			pkt.IPv = ip4.Version

		case layers.LayerTypeIPv6:
			ip6l := packet.Layer(layers.LayerTypeIPv6)
			ip6, ok := ip6l.(*layers.IPv6)
			if !ok {
				return nil, nil
			}
			pkt.Ip6 = NewIP6(ip6)
			pkt.IPv = ip6.Version
		case layers.LayerTypeTCP:
			tcpl := packet.Layer(layers.LayerTypeTCP)
			tcp, ok := tcpl.(*layers.TCP)
			if !ok {
				break
			}
			pkt.Tcp, pkt.PktType = NewTCP(tcp)
			return pkt, nil
		case layers.LayerTypeUDP:
			udpl := packet.Layer(layers.LayerTypeUDP)
			udp, ok := udpl.(*layers.UDP)
			if !ok {
				break
			}
			pkt.Udp, pkt.PktType = NewUDP(udp)
		case layers.LayerTypeDNS:
			dnsl := packet.Layer(layers.LayerTypeDNS)
			dns, ok := dnsl.(*layers.DNS)
			if !ok {
				break
			}
			pkt.Dns, pkt.PktType = NewDNS(dns)
			return pkt, nil
		}
	}
	return
}
