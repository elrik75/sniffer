package main

import (
    "flag"
    "fmt"
    "math"
    "os"
    "os/signal"
    "runtime"
    "runtime/pprof"
    "syscall"
    "time"

    // internal
    "clock"
    "data"
    "dump"
    "pcap"
)

var CONFIG map[string]string

func main() {
    CONFIG = get_opts()
    if CONFIG["listdevice"] == "true" {
        show_devices()
        os.Exit(0)
    }
    if CONFIG["profile"] == "true" {
        active_profiling()
        defer pprof.StopCPUProfile()
    }

    if CONFIG["debug"] == "true" {
        fmt.Printf("pcap version: %s\n", pcap.Version())
        fmt.Printf("Go version: %s\n", runtime.Version())
    }

    init_maps()
    pcapreader := create_reader()
    quit_chan := make(chan bool)

    go signalCatcher(pcapreader)
    go readPackets(pcapreader, quit_chan)
    controler(pcapreader, quit_chan)
}

func init_maps() {
    data.ETHMAP = new(data.PMap)
    seconds_60 := time.Duration(60 * math.Pow(10, 9))
    data.ETHMAP.Init(seconds_60)
    data.IPv4MAP = new(data.PMap)
    data.IPv4MAP.Init(seconds_60)
    data.TcpMAP = new(data.PMap)
    data.TcpMAP.Init(seconds_60)
    clock.InitClock()
}

func get_opts() map[string]string {
    config := make(map[string]string)

    var device, filename, expr, dumpproto string
    var listdevice, profile, debug bool

    flag.StringVar(&device, "i", "", "network interface")
    flag.StringVar(&filename, "r", "", "input pcap file")
    flag.StringVar(&expr, "e", "", "filter expression")
    flag.StringVar(&dumpproto, "p", "tcp", "protocols to dump")
    flag.BoolVar(&listdevice, "l", false, "just list devices and exit")
    flag.BoolVar(&debug, "d", false, "debug mode")
    flag.BoolVar(&profile, "profile", false, "activate profiling")
    flag.Parse()

    config["debug"] = fmt.Sprintf("%t", debug)
    config["device"] = device
    config["filename"] = filename
    config["expr"] = expr
    config["listdevice"] = fmt.Sprintf("%t", listdevice)
    config["profile"] = fmt.Sprintf("%t", profile)
    config["dumpproto"] = dumpproto
    return config
}

func active_profiling() {
    fp, err := os.Create("profiling.pprof")
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

func create_reader() *pcap.Pcap {
    var pcapreader *pcap.Pcap
    var err error

    if CONFIG["device"] != "" {
        pcapreader, err = pcap.Openlive(CONFIG["device"], 65535, true, 0)
        if err != nil {
            fmt.Printf("Openlive(%s) failed: %s\n", CONFIG["device"], err)
            os.Exit(1)
        }
    } else if CONFIG["filename"] != "" {
        pcapreader, err = pcap.Openoffline(CONFIG["filename"])
        if err != nil {
            fmt.Printf("Openoffline(%s) failed: %s\n", CONFIG["filename"], err)
            os.Exit(2)
        }
    } else {
        fmt.Printf("usage: pcaptest [-i <iface> | -r <pcap file>]\n")
        os.Exit(3)
    }
    return pcapreader
}

func readPackets(pcapreader *pcap.Pcap, quit_chan chan bool) {
    count := 0
    timebegin := time.Now()
    for pkt := pcapreader.Next(); pkt != nil; pkt = pcapreader.Next() {
        go launchParser(pkt)
        count += 1
        if count%1000000 == 0 {
            fmt.Println("num pkts=", count, "in", time.Now().Sub(timebegin))
            timebegin = time.Now()
        }
    }
    fmt.Print("Nothing more to read\n")
    quit_chan <- true
}

func launchParser(pkt *pcap.Packet) {
    ethpkt := data.ParseEthernet(data.ETHMAP, pkt, CONFIG)
    clock.Clock.Set(ethpkt.Time)
    if ethpkt.Type == 0x800 {
        data.ParseIpv4(data.IPv4MAP, ethpkt, CONFIG)
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
    timebegin := time.Now()

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
            fmt.Printf("TCP routines: %d\n", len(data.TcpMAP.StatsChans))
            for _, chans := range data.TcpMAP.StatsChans {
                chans.Control <- "<kill>"
            }
            break MAIN

        case <-clock.Clock.DumpChan:

            dumpbegin := time.Now()
            pcapreader.Paused = true
            dump.WriteEthernet(CONFIG, data.ETHMAP)
            dump.WriteIpv4(CONFIG, data.IPv4MAP)
            dump.WriteTcp(CONFIG, data.TcpMAP)
            pcapreader.Paused = false

            if CONFIG["debug"] == "true" {
                fmt.Println("<< END DUMPS ", time.Now().Sub(dumpbegin),
                    clock.Clock.Get(), "\n")
            }
        }
    }
    fmt.Println("controler ends, total time:", time.Now().Sub(timebegin))
}
