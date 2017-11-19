package applayer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/Acey9/pandafr/decoder"
	"github.com/google/gopacket/layers"
	"sort"
)

const (
	TypeHandshake   uint8 = 0x16
	TypeClientHello uint8 = 0x01
	TypeServerHello uint8 = 0x02
	TypeCertificate uint8 = 0x0b
)

type TcpPiece struct {
	Seq     uint32
	Payload []byte
}

type FlowID string

type TcpPieceList []*TcpPiece

func (p TcpPieceList) Len() int           { return len(p) }
func (p TcpPieceList) Less(i, j int) bool { return p[i].Seq < p[j].Seq }
func (p TcpPieceList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

type SSL struct {
	worker       Worker
	flowRestruct map[string]TcpPieceList
}
type RecordLayer struct {
	Type     uint8
	VersionH uint8
	VersionL uint8
	Length   uint16
}

type HandshakeLayer struct {
	Type     uint8
	VersionH uint8
	VersionL uint8
	Length   uint32
}

func (ssl *SSL) Parser(pkt *decoder.Packet) (err error) {
	var proto layers.IPProtocol
	if pkt.IPv == 4 {
		proto = pkt.Ip4.Protocol
	} else {
		proto = pkt.Ip6.NextHeader
	}
	if proto != 6 {
		return
	}

	if len(pkt.Tcp.Payload) == 0 {
		return
	}
	flowID := pkt.Flow.FlowID()

	_, ok := ssl.flowRestruct[flowID]
	if !ok && pkt.Tcp.Payload[0] != TypeHandshake {
		return
	}

	piece := &TcpPiece{
		Seq:     pkt.Tcp.Seq,
		Payload: pkt.Tcp.Payload,
	}
	ssl.flowRestruct[flowID] = append(ssl.flowRestruct[flowID], piece)
	return
}

func (ssl *SSL) Complete() (err error) {
	for flowid, tcpPiece := range ssl.flowRestruct {
		fmt.Println("1", flowid)

		sort.Sort(tcpPiece)

		var payload []byte
		for _, piece := range tcpPiece {
			payload = append(payload, piece.Payload...)
		}
		err = ssl.extractCerts(payload)
		if err != nil {
			continue
		}
		fmt.Println("2", flowid)
	}
	return
}

func NewSSL() *SSL {
	ssl := &SSL{
		flowRestruct: make(map[string]TcpPieceList),
	}
	return ssl
}

func (ssl *SSL) extractCerts(payload []byte) (err error) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("error: %v\n", err)
		}
	}()
	return ssl.extract(payload)
}

func (ssl *SSL) extract(payload []byte) (err error) {
	if len(payload) == 0 {
		err = errors.New("payload is empty.")
		return
	}
	fmt.Printf("payload:% 2x\n", payload)
	rl, err := NewRecordLayer(payload)
	if err != nil {
		return
	}

	hs, err := NewHandshakeLayer(payload)
	if err != nil {
		return
	}

	if rl.Type != TypeHandshake && (hs.Type != TypeClientHello || hs.Type != TypeServerHello) {
		err = errors.New("unknown protocol.")
		return err
	}

	rlSize := binary.Size(rl)

	certPayload := payload[uint32(rl.Length)+uint32(rlSize):]

	rl, err = NewRecordLayer(certPayload)
	if err != nil {
		return
	}

	if rl.Type != TypeHandshake {
		err = errors.New("unknown protocol.")
		return
	}

	fmt.Println(rl)
	fmt.Printf("% 2x\n", certPayload)
	if certPayload[5] != TypeCertificate {
		err = errors.New("unknown protocol.")
		return
	}
	certsLen := binary.BigEndian.Uint32(certPayload[9:13])
	certsLen = certsLen >> 8
	fmt.Println("xxxaadf:", certsLen)

	fmt.Printf("rl.Length:%d\tpayload.len:%d\n", rl.Length, len(certPayload))

	certPayload = certPayload[12 : 12+certsLen]
	var offset uint32
	totalLen := len(certPayload)
	for {
		if offset >= uint32(totalLen) {
			break
		}
		certLen := binary.BigEndian.Uint32(certPayload[0:4])
		certLen = certLen >> 8

		certPayload = certPayload[3:]
		cert := certPayload[:certLen]

		fmt.Printf("cert:\t% 2x\n", cert)
		certPayload = certPayload[certLen:]

		offset += certLen + 3
	}
	return
}
func NewRecordLayer(data []byte) (rl *RecordLayer, err error) {
	if len(data) == 0 {
		err = errors.New("payload is empty.")
		return
	}

	rl = &RecordLayer{}
	rl.Type = data[0]

	rl.VersionH = data[1]
	rl.VersionL = data[2]
	rl.Length = binary.BigEndian.Uint16(data[3:5])
	return
}

func NewHandshakeLayer(data []byte) (handshake *HandshakeLayer, err error) {
	if len(data) == 0 {
		err = errors.New("payload is empty.")
		return
	}

	handshake = &HandshakeLayer{}
	handshake.Type = data[5]

	buf := data[5:9]
	handshake.Length = binary.BigEndian.Uint32(buf) & 0xfff

	handshake.VersionH = data[9]
	handshake.VersionL = data[10]

	return
}
