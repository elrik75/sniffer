package pcap

/* copyright from https://github.com/akrennmair/gopcap */
/* just modify the Packet structure */

/*
#cgo LDFLAGS: -lpcap
#include <stdlib.h>
#include <pcap.h>

int hack_pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header,
                     u_char **pkt_data) {
   return pcap_next_ex(p, pkt_header, (const u_char **)pkt_data);
 }
*/
import "C"

import (
	"unsafe"
	"time"
	"syscall"
	"errors"
	"net"
	"fmt"
)

const (
	ERRBUF_SIZE = 256
)

// PCAP reader

type Pcap struct {
	cptr *C.pcap_t
	Paused bool
}

func (p *Pcap) Next() (pkt *Packet) { 
	paused := false
	if p.Paused {
		fmt.Print("(reader paused)\n")
		paused = true
	}
	for p.Paused {
		time.Sleep(10000000)
	}

	if paused {
		fmt.Print("(reader unpaused)\n")
		paused = false
	}
	rv, _ := p.NextEx()
	return rv
}

func (p *Pcap) NextEx() (pkt *Packet, result int32) {
	var pkthdr_ptr *C.struct_pcap_pkthdr
	var pkthdr C.struct_pcap_pkthdr

	var buf_ptr *C.u_char
	var buf unsafe.Pointer
	result = int32(C.hack_pcap_next_ex(p.cptr, &pkthdr_ptr, &buf_ptr))

	buf = unsafe.Pointer(buf_ptr)
	pkthdr = *pkthdr_ptr

	if nil == buf {
		return
	}
	pkt = new(Packet)
	pkt.Time = time.Unix(int64(pkthdr.ts.tv_sec), int64(pkthdr.ts.tv_usec))
	pkt.Caplen = uint32(pkthdr.caplen)
	pkt.Len = uint32(pkthdr.len)
	pkt.Data = make([]byte, pkthdr.caplen)

	for i := uint32(0); i < pkt.Caplen; i++ {
		pkt.Data[i] = *(*byte)(unsafe.Pointer(uintptr(buf) + uintptr(i)))
	}
	return
}

func (p *Pcap) Close() {
	C.pcap_close(p.cptr)
}

func (p *Pcap) Geterror() error {
	return errors.New(C.GoString(C.pcap_geterr(p.cptr)))
}

func (p *Pcap) Setfilter(expr string) (err error) {
	var bpf _Ctype_struct_bpf_program
	cexpr := C.CString(expr)
	defer C.free(unsafe.Pointer(cexpr))

	if -1 == C.pcap_compile(p.cptr, &bpf, cexpr, 1, 0) {
		return p.Geterror()
	}

	if -1 == C.pcap_setfilter(p.cptr, &bpf) {
		C.pcap_freecode(&bpf)
		return p.Geterror()
	}
	C.pcap_freecode(&bpf)
	return nil
}

func (p *Pcap) Datalink() int {
	return int(C.pcap_datalink(p.cptr))
}

func (p *Pcap) Setdatalink(dlt int) error {
	if -1 == C.pcap_set_datalink(p.cptr, C.int(dlt)) {
		return p.Geterror()
	}
	return nil
}

func (p *Pcap) Inject(data []byte) (err error) {
	buf := (*C.char)(C.malloc((C.size_t)(len(data))))

	for i := 0; i < len(data); i++ {
		*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(buf)) + uintptr(i))) = data[i]
	}

	if -1 == C.pcap_inject(p.cptr, unsafe.Pointer(buf), (C.size_t)(len(data))) {
		err = p.Geterror()
	}
	C.free(unsafe.Pointer(buf))
	return
}

// PACKET

type Interface struct {
	Name        string
	Description string
	Addresses   []IFAddress
	// TODO: add more elements
}

type IFAddress struct {
	IP      net.IP
	Netmask net.IPMask
	// TODO: add broadcast + PtP dst ?
}

type Packet struct {
	Time   time.Time // packet send/receive time
	Caplen uint32    // bytes stored in the file (caplen <= len)
	Len    uint32    // bytes sent/received
	Data   []byte    // packet data

	Type    int      // protocol type, see LINKTYPE_*
	DestMac uint64
	SrcMac  uint64

	Payload []byte   // remaining non-header bytes
	Vlan    int      // Vlan ID
}
// PACKET
func (pkt *Packet) Show() string {
	return fmt.Sprintf("src[%16x] dst[%16x] Type[%4x]",
		pkt.SrcMac, pkt.DestMac, pkt.Type)
}

func (pkt *Packet) GetTime() time.Time {
	return pkt.Time
}

// Openlive opens a device and returns a *Pcap handler
func Openlive(device string, snaplen int32, promisc bool, timeout_ms int32) (handle *Pcap, err error) {
	var buf *C.char
	buf = (*C.char)(C.calloc(ERRBUF_SIZE, 1))
	h := new(Pcap)
	h.Paused = false
	var pro int32
	if promisc {
		pro = 1
	}

	dev := C.CString(device)
	defer C.free(unsafe.Pointer(dev))

	h.cptr = C.pcap_open_live(dev, C.int(snaplen), C.int(pro), C.int(timeout_ms), buf)
	if nil == h.cptr {
		handle = nil
		err = errors.New(C.GoString(buf))
	} else {
		handle = h
	}
	C.free(unsafe.Pointer(buf))
	return
}


func Openoffline(file string) (handle *Pcap, err error) {
	var buf *C.char
	buf = (*C.char)(C.calloc(ERRBUF_SIZE, 1))
	h := new(Pcap)
	h.Paused = false

	cf := C.CString(file)
	defer C.free(unsafe.Pointer(cf))

	h.cptr = C.pcap_open_offline(cf, buf)
	if nil == h.cptr {
		handle = nil
		err = errors.New(C.GoString(buf))
	} else {
		handle = h
	}
	C.free(unsafe.Pointer(buf))
	return
}


func Version() string {
	return C.GoString(C.pcap_lib_version())
}


func DatalinkValueToName(dlt int) string {
	if name := C.pcap_datalink_val_to_name(C.int(dlt)); name != nil {
		return C.GoString(name)
	}
	return ""
}


func DatalinkValueToDescription(dlt int) string {
	if desc := C.pcap_datalink_val_to_description(C.int(dlt)); desc != nil {
		return C.GoString(desc)
	}
	return ""
}


func Findalldevs() (ifs []Interface, err error) {
	var buf *C.char
	buf = (*C.char)(C.calloc(ERRBUF_SIZE, 1))
	defer C.free(unsafe.Pointer(buf))
	var alldevsp *C.pcap_if_t

	if -1 == C.pcap_findalldevs((**C.pcap_if_t)(&alldevsp), buf) {
		return nil, errors.New(C.GoString(buf))
	}
	defer C.pcap_freealldevs((*C.pcap_if_t)(alldevsp))
	dev := alldevsp
	var i uint32
	for i = 0; dev != nil; dev = (*C.pcap_if_t)(dev.next) {
		i++
	}
	ifs = make([]Interface, i)
	dev = alldevsp
	for j := uint32(0); dev != nil; dev = (*C.pcap_if_t)(dev.next) {
		var iface Interface
		iface.Name = C.GoString(dev.name)
		iface.Description = C.GoString(dev.description)
		iface.Addresses = findalladdresses(dev.addresses)
		// TODO: add more elements
		ifs[j] = iface
		j++
	}
	return
}


func findalladdresses(addresses *_Ctype_struct_pcap_addr) (retval []IFAddress) {
	// TODO - make it support more than IPv4 and IPv6?
	retval = make([]IFAddress, 0, 1)
	for curaddr := addresses; curaddr != nil; curaddr = (*_Ctype_struct_pcap_addr)(curaddr.next) {
		var a IFAddress
		var err error
		if a.IP, err = sockaddr_to_IP((*syscall.RawSockaddr)(unsafe.Pointer(curaddr.addr))); err != nil {
			continue
		}
		if a.Netmask, err = sockaddr_to_IP((*syscall.RawSockaddr)(unsafe.Pointer(curaddr.addr))); err != nil {
			continue
		}
		retval = append(retval, a)
	}
	return
}


func sockaddr_to_IP(rsa *syscall.RawSockaddr) (IP []byte, err error) {
	switch rsa.Family {
	case syscall.AF_INET:
		pp := (*syscall.RawSockaddrInet4)(unsafe.Pointer(rsa))
		IP = make([]byte, 4)
		for i := 0; i < len(IP); i++ {
			IP[i] = pp.Addr[i]
		}
		return
	case syscall.AF_INET6:
		pp := (*syscall.RawSockaddrInet6)(unsafe.Pointer(rsa))
		IP = make([]byte, 16)
		for i := 0; i < len(IP); i++ {
			IP[i] = pp.Addr[i]
		}
		return
	}
	err = errors.New("Unsupported address type")
	return
}
