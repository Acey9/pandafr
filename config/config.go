package config

import (
	"github.com/Acey9/apacket/logp"
)

var Cfg Config

type Config struct {
	Logging   *logp.Logging
	LogServer string
	Iface     *InterfacesConfig
}

type InterfacesConfig struct {
	File      string
	BpfFilter string
	Dumpfile  string
}
