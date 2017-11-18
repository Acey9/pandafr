package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/Acey9/apacket/logp"
	"github.com/Acey9/pandafr/applayer"
	"github.com/Acey9/pandafr/config"
	"github.com/Acey9/pandafr/decoder"
	"github.com/Acey9/pandafr/sniffer"
	"github.com/google/gopacket"
	"os"
	"runtime"
)

const version = "v0.10"

type Applayer interface {
	Parser(pkt *decoder.Packet)
}

type Pandafr struct {
	//decoder
	decoder        *decoder.Decoder
	applayerWorker map[string]applayer.Worker
}

func (pandafr *Pandafr) OnPacket(data []byte, ci *gopacket.CaptureInfo) {
	//fmt.Println(data)
	pkt, err := pandafr.decoder.Process(data, ci)
	if err != nil {
		logp.Err("%v", err)
		return
	}
	for _, wk := range pandafr.applayerWorker {
		//TODO
		wk.Parser(pkt)
	}
	b, err := json.Marshal(pkt)
	if err != nil {
		logp.Err("%s", err)
		return
	}
	logp.Info(" pkt %s", b)
}

func optParse() {

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s [option] [BpfFilter]\n", os.Args[0])
		flag.PrintDefaults()
	}

	var ifaceConfig config.InterfacesConfig
	var logging logp.Logging
	var fileRotator logp.FileRotator
	var rotateEveryKB uint64
	var keepFiles int

	//flag.StringVar(&ifaceConfig.BpfFilter, "f", "", "BPF filter")
	flag.StringVar(&ifaceConfig.File, "f", "", "Read packets from file")
	flag.StringVar(&ifaceConfig.Dumpfile, "df", "", "Dump to file")

	flag.StringVar(&logging.Level, "l", "info", "Logging level")
	flag.StringVar(&fileRotator.Path, "p", "", "Log path")
	flag.StringVar(&fileRotator.Name, "n", "pandafr.log", "Log filename")
	flag.Uint64Var(&rotateEveryKB, "r", 10240, "The size of each log file.(KB)")
	flag.IntVar(&keepFiles, "k", 7, "Keep the number of log files")

	flag.StringVar(&config.Cfg.LogServer, "ls", "", "Log server address.The log will send to this server")

	printVersion := flag.Bool("V", false, "Version")

	flag.Parse()

	args := flag.Args()
	if len(args) > 0 {
		ifaceConfig.BpfFilter = args[0]
	}
	if *printVersion {
		fmt.Fprintf(os.Stderr, "%s\n", version)
		os.Exit(0)
	}

	config.Cfg.Iface = &ifaceConfig

	logging.Files = &fileRotator
	if logging.Files.Path != "" {
		tofiles := true
		logging.ToFiles = &tofiles

		rotateKB := rotateEveryKB * 1024
		logging.Files.RotateEveryBytes = &rotateKB
		logging.Files.KeepFiles = &keepFiles
	}
	config.Cfg.Logging = &logging

	if ifaceConfig.File == "" {
		flag.Usage()
		os.Exit(1)
	}
}

func init() {
	optParse()
	logp.Init("pandafr", config.Cfg.Logging)
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	worker := &Pandafr{
		applayerWorker: make(map[string]applayer.Worker),
	}

	worker.applayerWorker["ssl"] = applayer.NewSSL()
	//TODO
	//worker.applayerWorker["http"] = &applayer.HTTP{}

	sniff := &sniffer.SnifferSetup{}
	err := sniff.Init(config.Cfg.Iface, worker)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
	}
	sniff.Run()
	defer sniff.Close()
}
