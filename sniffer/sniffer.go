package sniffer

import (
	"fmt"
	"github.com/Acey9/pandafr/config"
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
	isAlive    bool
	worker     Worker
	dataSource gopacket.PacketDataSource
}

func (sniffer *SnifferSetup) Init(iFace *config.InterfacesConfig, worker Worker) (err error) {
	handle, err := pcap.OpenOffline(iFace.File)
	if err != nil {
		return
	}
	sniffer.pcapHandle = handle
	sniffer.filter = iFace.BpfFilter
	err = sniffer.pcapHandle.SetBPFFilter(sniffer.filter)
	if err != nil {
		return
	}
	sniffer.dataSource = gopacket.PacketDataSource(sniffer.pcapHandle)
	sniffer.worker = worker
	sniffer.isAlive = true
	return
}

func (sniffer *SnifferSetup) Close() error {
	sniffer.pcapHandle.Close()
	return nil
}

func (sniffer *SnifferSetup) Run() (retError error) {
	for sniffer.isAlive {
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
	return
}
