package dump

import (
	"fmt"
	"strings"
	"os"
	"io"

	// internal
	"clock"
	"data"
)


func WriteEthernet(config map[string]string, pmap *data.PMap) {
	var fd *os.File

	if config["debug"] == "true" {
		fmt.Printf("ETH routines: %d\n", len(pmap.StatsChans))
	}

	if strings.Contains(config["dumpproto"], "eth") {
		fd = create_file("eth")
		for _, chans := range data.ETHMAP.StatsChans {
			chans.Control <- "<dump><reset><timeout>"
			result := <-chans.Results
			write_stats(fd, result)
		}
		close_file(fd)
	} else {
		for _, chans := range pmap.StatsChans {
			chans.Control <- "<timeout>"
		}
	}
}


func WriteIpv4(config map[string]string, pmap *data.PMap) {
	var fd *os.File

	if config["debug"] == "true" {
		fmt.Printf("IP  routines: %d\n", len(pmap.StatsChans))
	}

	if strings.Contains(config["dumpproto"], "ip") {
		fd = create_file("ipv4")
		for _, chans := range pmap.StatsChans {
			chans.Control <- "<dump><reset><timeout>"
			result := <-chans.Results
			write_stats(fd, result)
		}
		close_file(fd)
	} else {
		for _, chans := range pmap.StatsChans {
			chans.Control <- "<timeout>"
		}
	}
}


func WriteTcp(config map[string]string, pmap *data.PMap) {
	var fd *os.File

	if config["debug"] == "true" {
		fmt.Printf("TCP routines: %d\n", len(pmap.StatsChans))
	}

	if strings.Contains(config["dumpproto"], "tcp") {
		fd = create_file("tcp")
		for _, chans := range pmap.StatsChans {
			chans.Control <- "<dump><reset><timeout>"
			result := <-chans.Results
			write_stats(fd, result)
		}
		close_file(fd)
	} else {
		for _, chans := range pmap.StatsChans {
			chans.Control <- "<timeout>"
		}
	}
}


func create_file(datatype string) *os.File {
    time := clock.Clock.GetForDump()
    filename := fmt.Sprintf("dump_%s_%d.csv", datatype, time)
    file, ok := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0664)
    if ok != nil {
        fmt.Println("Dump File Error:", ok)
    } else {
        return file
    }
    return nil
}

func write_stats(file *os.File, stat data.IStat) {
    if file == nil {
        return
    }
    txt := stat.CSVRow()
    io.WriteString(file, txt)
}

func close_file(file *os.File) {
    if file != nil {
        file.Close()
    }
}
