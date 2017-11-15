package main

import (
	"fmt"
	"github.com/Acey9/pandafr/sniffer"
	"github.com/google/gopacket"
)

type Pandafr struct {
}

func (pandafr *Pandafr) OnPacket(data []byte, ci *gopacket.CaptureInfo) {
	fmt.Println(data)
}

func main() {
	worker := &Pandafr{}
	sniff := &sniffer.SnifferSetup{}
	err := sniff.Init("./t.pcap", "not arp", worker)
	if err != nil {
		panic(err)
	}
	sniff.Run()
}
