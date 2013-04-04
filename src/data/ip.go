package data

import (
    "encoding/binary"
    "fmt"
    "time"

    //internal
    "pcap"
    "utils"
)

// GLOBAL ETH MAP
var IPv4MAP *PMap

// PACKET
type Ipv4Packet struct {
    EthPacket *pcap.Packet
    Protocol  uint8
	Id        uint16
    Checksum  uint16
    SrcIp     uint32
    DstIp     uint32
    Tos       uint8
    Length    uint16
    Payload   []byte
    Ihl       uint8
}

func (pkt *Ipv4Packet) Show() string {
    return fmt.Sprintf("src[%16x] dst[%16x] Protocol[%4x]",
        pkt.SrcIp, pkt.DstIp, pkt.Protocol)
}

func (pkt *Ipv4Packet) GetTime() time.Time {
    return pkt.EthPacket.Time
}

// MAP KEY
type Ipv4Key struct {
    Protocol uint8
    SrcIp    uint32
    DstIp    uint32
}

func (key *Ipv4Key) Show() string {
    return fmt.Sprintf("IPv4 src[%x=%s] dst[%x=%s] Protocol[%4x]",
        key.SrcIp, utils.EncodeIp(key.SrcIp),
        key.DstIp, utils.EncodeIp(key.DstIp),
        key.Protocol)
}

func (key *Ipv4Key) Number() uint16 {
    // seem to be bugged
    if key.SrcIp <= key.DstIp {
        return uint16(key.SrcIp % uint32(LOCKNUM))
    }
    return uint16(key.DstIp % uint32(LOCKNUM))
}

func (key *Ipv4Key) Serial() string {
    if key.SrcIp <= key.DstIp {
        return fmt.Sprintf("%x-%x-%x", key.SrcIp, key.DstIp, key.Protocol)
    }
    return fmt.Sprintf("%x-%x-%x", key.DstIp, key.SrcIp, key.Protocol)
}

// STATS
type IpStat struct {
    key            *Ipv4Key
    PacketsSrc     uint64
    PacketsDst     uint64
    PayloadSizeSrc uint64
    PayloadSizeDst uint64
}

func (ipstat *IpStat) Show() string {
    return fmt.Sprintf("Payload: %d/%d kB\tPackets: %d/%d",
        ipstat.PayloadSizeSrc/1024, ipstat.PayloadSizeDst/1024,
        ipstat.PacketsSrc, ipstat.PacketsDst)
}

func (ipstat *IpStat) CSVRow() string {
    return fmt.Sprintf("%s|%s|%d|%d|%d|%d|%d\n",
        utils.EncodeIp(ipstat.key.SrcIp),
        utils.EncodeIp(ipstat.key.DstIp),
        ipstat.key.Protocol,
        ipstat.PayloadSizeSrc, ipstat.PayloadSizeDst,
        ipstat.PacketsSrc, ipstat.PacketsDst)
}

func (ipstat *IpStat) Copy() IStat {
    return &IpStat{
        ipstat.key,
        ipstat.PacketsSrc, ipstat.PacketsDst,
        ipstat.PayloadSizeSrc, ipstat.PayloadSizeDst}
}

func (ipstat *IpStat) Reset() {
    ipstat.PayloadSizeSrc = 0
    ipstat.PayloadSizeDst = 0
    ipstat.PacketsSrc = 0
    ipstat.PacketsDst = 0
}

func (ipstat *IpStat) AppendStat(key IKey, pkt IPacket) {
    ipkey := key.(*Ipv4Key)
    ippkt := pkt.(*Ipv4Packet)
    if ippkt.SrcIp == ipkey.SrcIp {
        ipstat.PayloadSizeSrc += uint64(ippkt.Length)
        ipstat.PacketsSrc += 1
    } else {
        ipstat.PayloadSizeDst += uint64(ippkt.Length)
        ipstat.PacketsDst += 1
    }
}

// PACKET PARSER
func ParseIpv4(ipmap *PMap, pkt *pcap.Packet) {
    ip := new(Ipv4Packet)
    //fmt.Println(pkt.Payload)

    ip.EthPacket = pkt
    ip.Tos = pkt.Payload[1]
    ip.Length = binary.BigEndian.Uint16(pkt.Payload[2:4])
	ip.Id = binary.BigEndian.Uint16(pkt.Payload[4:6])
    ip.Protocol = pkt.Payload[9]
    ip.Checksum = binary.BigEndian.Uint16(pkt.Payload[10:12])
    ip.SrcIp = binary.BigEndian.Uint32(pkt.Payload[12:16])
    ip.DstIp = binary.BigEndian.Uint32(pkt.Payload[16:20])

    ip.Payload = pkt.Payload[ip.Ihl*4:]

    key := Ipv4Key{ip.Protocol, ip.SrcIp, ip.DstIp}
    is_new, chans := ipmap.InitValue(&key)
    if is_new {
        //fmt.Println("NEW routine:", key.Show())

        stats := new(IpStat)
        stats.key = &key
        go Handler(ipmap, &key, stats)
    }
    chans.Inputs <- ip
}
