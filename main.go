package main

import (
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"runtime/pprof"
	"syscall"
	"time"

	"github.com/akrennmair/gopcap"

	"data"
)

var (
	DUMPPERIOD = time.Duration(1800 * math.Pow(10, 9))
)

func main() {
	fmt.Printf("pcap version: %s\n", pcap.Version())
	config := get_opts()
	if config["listdevice"] == "true" {
		show_devices()
		os.Exit(0)
	}
	if config["profile"] == "true" {
		active_profiling()
		defer pprof.StopCPUProfile()
	}

	init_maps()
	pcapreader := create_reader(config)
	quit_chan := make(chan bool)

//	go signalCatcher(pcapreader)
	go readPackets(pcapreader, quit_chan)
	controler(pcapreader, quit_chan)
}

func init_maps() {
	data.ETHMAP = new(data.PMap)
	seconds_120 := time.Duration(1800 * math.Pow(10, 9))
	data.ETHMAP.Init(seconds_120)
	data.IPv4MAP = new(data.PMap)
	data.IPv4MAP.Init(seconds_120)
}

func get_opts() map[string]string {
	config := make(map[string]string)

	var device, filename, expr string
	var listdevice, profile bool

	flag.StringVar(&device, "i", "", "network interface")
	flag.StringVar(&filename, "r", "", "input pcap file")
	flag.StringVar(&expr, "e", "", "filter expression")
	flag.BoolVar(&listdevice, "l", false, "just list devices and exit")
	flag.BoolVar(&profile, "profile", false, "activate profiling")
	flag.Parse()

	config["device"] = device
	config["filename"] = filename
	config["expr"] = expr
	config["listdevice"] = fmt.Sprintf("%t", listdevice)
	config["profile"] = fmt.Sprintf("%t", profile)
	return config
}

func active_profiling() {
	fp, err := os.Create("/tmp/profiling")
	if err != nil {
		fmt.Print(err)
		os.Exit(4)
		return
	}
	pprof.StartCPUProfile(fp)
}

func show_devices() {
	ifs, err := pcap.Findalldevs()
	if len(ifs) == 0 {
		fmt.Print("Warning: no devices found.\n")
		if err != nil {
			fmt.Printf("Error: %s\n", err)
		} else {
			fmt.Print("Maybe you have not the good rights\n")
		}
	} else {
		for i, _ := range ifs {
			fmt.Printf("dev %d: %s (%s)\n", i+1, ifs[i].Name, ifs[i].Description)
		}
	}
}

func create_reader(config map[string]string) *pcap.Pcap {
	var pcapreader *pcap.Pcap
	var err error

	if config["device"] != "" {
		pcapreader, err = pcap.Openlive(config["device"], 65535, true, 0)
		if err != nil {
			fmt.Printf("Openlive(%s) failed: %s\n", config["device"], err)
			os.Exit(1)
		}
	} else if config["filename"] != "" {
		pcapreader, err = pcap.Openoffline(config["filename"])
		if err != nil {
			fmt.Printf("Openoffline(%s) failed: %s\n", config["filename"], err)
			os.Exit(2)
		}
	} else {
		fmt.Printf("usage: pcaptest [-i <iface> | -f <pcap file>]\n")
		os.Exit(3)
	}
	return pcapreader
}

func readPackets(pcapreader *pcap.Pcap, quit_chan chan bool) {
	for pkt := pcapreader.Next(); pkt != nil; pkt = pcapreader.Next() {
		go launchParser(pkt)
	}
	quit_chan <- true
}


func launchParser(pkt *pcap.Packet) {
	ethpkt := data.ParseEthernet(data.ETHMAP, pkt)
	if ethpkt.Type == 0x800 {
		go data.ParseIpv4(data.IPv4MAP, ethpkt)
	}
}

func signalCatcher(pcapreader *pcap.Pcap) {
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT)
	<-ch
	fmt.Println("CTRL-C; exiting")
	pcapreader.Close()
}

func controler(pcapreader *pcap.Pcap, quit_chan chan bool) {
	timer := time.NewTicker(DUMPPERIOD)
	defer timer.Stop()

MAIN:
	for {
		select {
		case <-quit_chan:
			fmt.Print("\nEND\n")
			fmt.Printf("ETH routines: %d\n", len(data.ETHMAP.StatsChans))
			for _, chans := range data.ETHMAP.StatsChans {
				chans.Control <- "<kill>"
			}
			fmt.Printf("IP  routines: %d\n", len(data.IPv4MAP.StatsChans))
			for _, chans := range data.IPv4MAP.StatsChans {
				chans.Control <- "<kill>"
			}
			fmt.Print("IP ends\n")
			break MAIN

		case <-timer.C:
			fmt.Print("Time to dump:\n")
			for _, chans := range data.ETHMAP.StatsChans {
				chans.Control <- "<dump><reset>"
				<-chans.Results
				//result := <-chans.Results
				//fmt.Printf(" * %s\n  %s\n", k, result.Show())
			}
			for _, chans := range data.IPv4MAP.StatsChans {
				chans.Control <- "<dump><reset>"
				<-chans.Results
				//result := <-chans.Results
				//fmt.Printf(" * %s\n  %s\n", k, result.Show())
			}
			fmt.Print("\n")
		}
	}
	fmt.Print("controler ends\n")
}
