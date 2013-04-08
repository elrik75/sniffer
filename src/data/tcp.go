package data

import (
    "encoding/binary"
    "fmt"
	"time"

	"utils"
)

// GLOBAL TCP MAP
var TcpMAP *PMap

// PACKET
type TcpPacket struct {
	Ipv4Packet *Ipv4Packet

	SrcPort uint16
	DstPort uint16
	Seq uint32
	Ack uint32
	DataOffset uint8
	Flags uint16
	Window uint16
	Checksum uint16
	Urgent uint16
	Payload []byte
}

func (pkt *TcpPacket) Show() string {
	return fmt.Sprintf("src[%x-%x] dst[%x-%x] Seq[%x]",
		pkt.Ipv4Packet.SrcIp, pkt.SrcPort,
		pkt.Ipv4Packet.DstIp, pkt.DstPort,
		pkt.Seq)
}

func (pkt *TcpPacket) GetTime() time.Time {
	return pkt.Ipv4Packet.GetTime()
}


// MAP KEY
type TcpKey struct {
	Ipv4Key Ipv4Key

	SrcPort uint16
	DstPort uint16
}

func (key *TcpKey) Show() string {
	return fmt.Sprintf("src[%x/%x] dst[%x/%x]",
		key.Ipv4Key.SrcIp, key.Ipv4Key.DstIp,
		key.SrcPort, key.DstPort)
}

func (key *TcpKey) Serial() ISerial {
	if key.SrcPort < key.DstPort {
		return *key
	}
	return TcpKey{key.Ipv4Key, key.SrcPort, key.DstPort}
}


// STATS
type TcpStat struct {
	key *TcpKey
	count_syn uint16
	count_ack uint16
	PayloadSizeSrc uint64
	PayloadSizeDst uint64
}

func (tcpstat *TcpStat) Show() string {
	return fmt.Sprintf("Payload: %d/%d kB\n", 
		tcpstat.PayloadSizeSrc, tcpstat.PayloadSizeDst)
}

func (tcpstat *TcpStat) CSVRow() string {
	return fmt.Sprintf("%s|%s|%d|%d|%d|%d|%d|%d\n",
		utils.EncodeIp(tcpstat.key.Ipv4Key.SrcIp),
		utils.EncodeIp(tcpstat.key.Ipv4Key.DstIp),
		tcpstat.key.SrcPort, tcpstat.key.DstPort,
		tcpstat.PayloadSizeSrc, tcpstat.PayloadSizeDst,
		tcpstat.count_syn, tcpstat.count_ack)
}

func (tcpstat *TcpStat) Copy() IStat {
	return &TcpStat{
		tcpstat.key,
		tcpstat.count_syn, tcpstat.count_ack,
		tcpstat.PayloadSizeSrc, tcpstat.PayloadSizeDst}
}

func (tcpstat *TcpStat) Reset() {
	tcpstat.count_syn = 0
	tcpstat.count_ack = 0
	tcpstat.PayloadSizeSrc = 0
	tcpstat.PayloadSizeDst = 0
}

func (tcpstat *TcpStat) AppendStat(key IKey, pkt IPacket) {
	tcpkey := key.(*TcpKey)
	tcppkt := pkt.(*TcpPacket)
	if tcppkt.Ipv4Packet.SrcIp == tcpkey.Ipv4Key.SrcIp {
		tcpstat.PayloadSizeSrc += uint64(tcppkt.Ipv4Packet.Length)
	} else {
		tcpstat.PayloadSizeDst += uint64(tcppkt.Ipv4Packet.Length)
	}
}


// TCP PARSER
func TcpParser(tcpmap *PMap, pkt *Ipv4Packet, ipkey *Ipv4Key) {
	tcp := new(TcpPacket)

	tcp.Ipv4Packet = pkt
	tcp.SrcPort = binary.BigEndian.Uint16(pkt.Payload[0:2])
	tcp.DstPort = binary.BigEndian.Uint16(pkt.Payload[2:4])
	tcp.Seq = binary.BigEndian.Uint32(pkt.Payload[4:8])
	tcp.Ack = binary.BigEndian.Uint32(pkt.Payload[8:12])
	tcp.DataOffset = (pkt.Payload[12] & 0xF0) >> 4
	tcp.Flags = binary.BigEndian.Uint16(pkt.Payload[12:14]) & 0x1FF
	tcp.Window = binary.BigEndian.Uint16(pkt.Payload[14:16])
	tcp.Checksum = binary.BigEndian.Uint16(pkt.Payload[16:18])
	tcp.Urgent = binary.BigEndian.Uint16(pkt.Payload[18:20])
	tcp.Payload = pkt.Payload[tcp.DataOffset*4:]

	key := TcpKey{*ipkey, tcp.SrcPort, tcp.DstPort}
	is_new, chans := tcpmap.InitValue(&key)
	if is_new {
		stats := new(TcpStat)
		stats.key = &key
		go Handler(tcpmap, &key, stats)
	}
	chans.Inputs <- tcp
}
