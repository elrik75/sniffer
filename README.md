Go Sniffer
==========

This code aims to sniff the network (or a PCAP file) and generates stats in some CSV files.
The idea is to use a Go routine for each parser and then get a very simple code.

Install
-------

    export GOPATH=$PWD
    export GOMAXPROCS=8
    go build -o sniffer main.go

Sniff the network:

    sudo sniffer -i eth0

Or read a pcap file:

    sniffer -r file.pcap


Profiling
---------

- install graphviz

- run the sniffer with the `-profile` option

    ./sniffer -r file.pcap  -profile

- a file `profiling.pprof` was build

- generate a pdf with:

    go tool pprof --pdf sniffer profiling.pprof > profile.pdf
