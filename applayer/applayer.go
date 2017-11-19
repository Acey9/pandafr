package applayer

import (
	"github.com/Acey9/pandafr/decoder"
)

type Worker interface {
	Parser(pkt *decoder.Packet) (err error)
	Complete() (err error)
}
