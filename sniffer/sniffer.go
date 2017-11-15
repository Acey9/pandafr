package sniffer

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"io"
	"syscall"
)

type Worker interface {
	OnPacket(data []byte, ci *gopacket.CaptureInfo)
}

type SnifferSetup struct {
	pcapHandle *pcap.Handle
	filter     string
	worker     Worker
	dataSource gopacket.PacketDataSource
}

func (sniffer *SnifferSetup) setFromConfig() {
	//TODO
}

func (sniffer *SnifferSetup) Init(filePath, filter string, worker Worker) (err error) {
	handle, err := pcap.OpenOffline(filePath)
	if err != nil {
		return
	}
	sniffer.pcapHandle = handle
	err = sniffer.pcapHandle.SetBPFFilter(sniffer.filter)
	if err != nil {
		return
	}
	sniffer.dataSource = gopacket.PacketDataSource(sniffer.pcapHandle)
	sniffer.worker = worker
	return
}

func (sniffer *SnifferSetup) Run() (retError error) {
	for {
		data, ci, err := sniffer.dataSource.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired || err == syscall.EINTR {
			return
		}
		if err == io.EOF {
			//End of file
			return
		}
		if err != nil {
			retError = fmt.Errorf("Sniffing error: %s", err)
			return
		}

		if len(data) == 0 {
			// Empty packet, probably timeout from afpacket
			return
		}
		sniffer.worker.OnPacket(data, &ci)
	}

}
