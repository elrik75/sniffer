package data

import (
	"fmt"
	"encoding/binary"

	"github.com/akrennmair/gopcap"

	"utils"
)

// GLOBAL ETH MAP
var ETHMAP *PMap

const (
	PAYLOAD_MAX = 512
)

// PACKET
type EthPacket struct {
	pcap.Packet
	Vlan int
}
func (pkt *EthPacket) Show() string {
	return fmt.Sprintf("src[%16x] dst[%16x] Type[%4x]",
		pkt.SrcMac, pkt.DestMac, pkt.Type)
}

// MAP KEY
type EthKey struct {
	Type   int
	SrcMac uint64
	DstMac uint64
}

func (key *EthKey) Show() string {
	return fmt.Sprintf("Eth  src[%16x] dst[%16x] Type[%4x]",
		key.SrcMac, key.DstMac, key.Type)
}


func (key *EthKey) Number() uint8 {
	if key.SrcMac <=  key.DstMac {
		return uint8(key.SrcMac % uint64(LOCKNUM))
	}
	return uint8(key.DstMac %  uint64(LOCKNUM))
}

func (key *EthKey) Serial() string {
	if key.SrcMac <=  key.DstMac {
		return fmt.Sprintf("%x-%x-%x", key.SrcMac, key.DstMac, key.Type)
	}
	return fmt.Sprintf("%x-%x-%x", key.DstMac, key.SrcMac, key.Type)
}

// STATS

type EthStat struct {
	PayloadSizeSrc uint64
	PayloadSizeDst uint64
	PacketsSrc uint64
	PacketsDst uint64
}

func (ethstat *EthStat) Show() string {
	return fmt.Sprintf("Payload: %d/%d kB\tPackets: %d/%d",
		ethstat.PayloadSizeSrc/1024, ethstat.PayloadSizeDst/1024,
		ethstat.PacketsSrc, ethstat.PacketsDst)
}

func (ethstat *EthStat) Copy () IStat {
	return &EthStat{ethstat.PayloadSizeSrc, ethstat.PayloadSizeDst,
		            ethstat.PacketsSrc, ethstat.PacketsDst}
}

func (ethstat *EthStat) Reset () {
	ethstat.PayloadSizeSrc = 0
	ethstat.PayloadSizeDst = 0
	ethstat.PacketsSrc = 0
	ethstat.PacketsDst = 0
}

func (ethstat *EthStat) AppendStat (key IKey, pkt IPacket) {
	ethkey := key.(*EthKey)
	ethpkt := pkt.(*EthPacket)
	if ethpkt.SrcMac == ethkey.SrcMac {
		ethstat.PayloadSizeSrc += uint64(len(ethpkt.Payload))
		ethstat.PacketsSrc += 1
	} else {
		ethstat.PayloadSizeDst += uint64(len(ethpkt.Payload))
		ethstat.PacketsDst += 1
	}
}


// PACKET PARSER
func ParseEthernet(ethmap *PMap, pkt *pcap.Packet) *EthPacket {

	pkt.DestMac = utils.DecodeMac(pkt.Data[0:6])
	pkt.SrcMac = utils.DecodeMac(pkt.Data[6:12])

	ethtype := int(binary.BigEndian.Uint16(pkt.Data[12:14]))
	vlan := -1
	shift := 0
	if ethtype == 0x8100 {
		// VLAN TAG
		// TODO take last 12bits
		vlan = int(binary.BigEndian.Uint16(pkt.Data[14:16]))
		shift = 4
	}

	pkt.Type = int(binary.BigEndian.Uint16(pkt.Data[shift+12:shift+14]))
	pkt.Len = uint32(len(pkt.Data))

	max_size := utils.MinInt(len(pkt.Data), PAYLOAD_MAX+1)
	pkt.Payload = make([]byte, PAYLOAD_MAX)
	copy(pkt.Payload, pkt.Data[shift+14:max_size])
	pkt.Data = nil
	//fmt.Println(pkt.Show())
	key := EthKey{pkt.Type, pkt.SrcMac, pkt.DestMac}

	is_new, chans := ethmap.InitValue(&key)
	if is_new {
		//fmt.Println("NEW routine:", key.Show())
		stats := new(EthStat)
		go Handler(ethmap, &key, stats)
	}
	ethpkt :=  &EthPacket{*pkt, vlan}
	chans.Inputs <-ethpkt
	return ethpkt
}
