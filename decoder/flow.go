package decoder

import (
	"bytes"
	"net"
	"strconv"
)

type Flow struct {
	Sip, Dip     net.IP
	Sport, Dport uint16
}

func (f *Flow) FlowID() string {
	id := bytes.Buffer{}
	id.WriteString(f.Sip.String())
	id.WriteString(f.Dip.String())
	id.WriteString(strconv.Itoa(int(f.Sport)))
	id.WriteString(strconv.Itoa(int(f.Dport)))
	return id.String()
}
