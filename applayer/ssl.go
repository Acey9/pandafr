package applayer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/Acey9/pandafr/decoder"
)

type TcpPiece struct {
	Seq     uint64
	Payload []byte
}

type FlowID string

type SSL struct {
	worker       Worker
	flowRestruct map[string][]*TcpPiece
}
type RecordLayer struct {
	Type      uint8
	VersionH  uint8
	VersionL  uint8
	Length    uint16
	Handshake *HandshakeLayer
}

type HandshakeLayer struct {
	Type     uint8
	VersionH uint8
	VersionL uint8
	Length   uint32
}

func (ssl *SSL) Parser(pkt *decoder.Packet) {
	flowID := pkt.Flow.FlowID()
	piece := &TcpPiece{} //TODO set seq and payload
	ssl.flowRestruct[flowID] = append(ssl.flowRestruct[flowID], piece)
	fmt.Println(flowID, ssl.flowRestruct)
}

func NewSSL() *SSL {
	ssl := &SSL{
		flowRestruct: make(map[string][]*TcpPiece),
	}
	return ssl
}

func NewRecordLayer(data []byte) (ssl *RecordLayer, err error) {
	if len(data) == 0 {
		err = errors.New("Not ssl.")
		return
	}

	handshake := &HandshakeLayer{}
	ssl = &RecordLayer{
		Handshake: handshake,
	}
	ssl.Type = data[0]
	if ssl.Type != 0x16 {
		fmt.Println("ssl.Type:", ssl.Type, data)
		err = errors.New("Not ssl.")
		return
	}

	ssl.VersionH = data[1]
	ssl.VersionL = data[2]
	ssl.Length = binary.BigEndian.Uint16(data[3:5])

	ssl.Handshake.Type = data[5]

	buf := data[5:9]
	ssl.Handshake.Length = binary.BigEndian.Uint32(buf) & 0xfff

	ssl.Handshake.VersionH = data[9]
	ssl.Handshake.VersionL = data[10]

	return
}
