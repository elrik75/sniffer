package data

import (
//	"fmt"
	"strings"
	"sync"
	"time"
)

// PACKET
type IPacket interface {
	Show() string
}

// KEY
type IKey interface {
	Show() string
	Serial() string
	Number() uint16
}

// STAT
type IStat interface {
	Show() string
	Copy() IStat
	Reset()
	AppendStat(IKey, IPacket)
}

type StatsChans struct {
	Inputs  chan IPacket
	Results chan IStat
	Control chan string
}

const (
	// Number of locks to share to access to the map
	LOCKNUM uint16 = 65535
)

// MAP
type PMap struct {
	once       sync.Once
	mtx        map[uint16]*sync.Mutex
//	mtx        *sync.Mutex
	StatsChans map[string]*StatsChans
	timeout    time.Duration
}

func (pmap *PMap) GetLock(key IKey) *sync.Mutex {
//	number := key.Number()
//	fmt.Printf("%s: Use number %d\n", key.Show(), number)
//	fmt.Printf(".")
	return pmap.mtx[key.Number()]
//	return pmap.mtx
}

func (pmap *PMap) Init(timeout time.Duration) {
	pmap.once.Do(func() {
		pmap.StatsChans = make(map[string]*StatsChans, 2000)
//		pmap.mtx = new(sync.Mutex)
		pmap.mtx = make(map[uint16]*sync.Mutex, LOCKNUM)
		for i := uint16(0); i < LOCKNUM; i++ {
			pmap.mtx[i] = new(sync.Mutex)
		}
		pmap.timeout = timeout
	})
}

func (pmap *PMap) unsafeGet(key IKey) *StatsChans {
	return pmap.StatsChans[key.Serial()]
}

func (pmap *PMap) unsafeSet(key IKey, stats *StatsChans) {
	pmap.StatsChans[key.Serial()] = stats
}

func (pmap *PMap) Set(key IKey, stats *StatsChans) {
	lock := pmap.GetLock(key)
	lock.Lock()
	defer lock.Unlock()
	// pmap.mtx.Lock()
	// defer pmap.mtx.Unlock()
	pmap.unsafeSet(key, stats)
}

func (pmap *PMap) Get(key IKey) *StatsChans {
	lock := pmap.GetLock(key)
	lock.Lock()
	defer lock.Unlock()
	// pmap.mtx.Lock()
	// defer pmap.mtx.Unlock()
	return pmap.unsafeGet(key)
}

func (pmap *PMap) Delete(key IKey) {
	lock := pmap.GetLock(key)
	lock.Lock()
	defer lock.Unlock()
	// pmap.mtx.Lock()
	// defer pmap.mtx.Unlock()
	//fmt.Println("DEL routine:", key.Show())
	delete(pmap.StatsChans, key.Serial())
}

func (pmap *PMap) InitValue(key IKey) (bool, *StatsChans) {
	//key is a pointer
	lock := pmap.GetLock(key)
	lock.Lock()
	defer lock.Unlock()
	// pmap.mtx.Lock()
	// defer pmap.mtx.Unlock()

	var stats_chans *StatsChans
	stats_chans = pmap.unsafeGet(key)

	if stats_chans != nil {
		return false, stats_chans
	}

	data_chan := make(chan IPacket, 100)
	result_chan := make(chan IStat, 100)
	control_chan := make(chan string)
	stats_chans = &StatsChans{data_chan, result_chan, control_chan}
	pmap.unsafeSet(key, stats_chans)

	return true, stats_chans
}

func Handler(pmap *PMap, key IKey, stats IStat) {

	chans := pmap.Get(key)

	// TODO: Should not be a real time timer but should depend of the packets
	//       We need to have the same behavior between a device input than a PCAP file input.
	timout := time.NewTicker(pmap.timeout)
MAIN:
	for {
		select {
		case packet := <-chans.Inputs:
			timout.Stop()
			timout = time.NewTicker(pmap.timeout)
			stats.AppendStat(key, packet)

		case control := <-chans.Control:
			if strings.Contains(control, "<dump>") {
				chans.Results <- stats.Copy()
			}
			if strings.Contains(control, "<reset>") {
				stats.Reset()
			}
			if strings.Contains(control, "<kill>") {
				pmap.Delete(key)
				break MAIN
			}

		case <-timout.C:
			pmap.Delete(key)
			break MAIN
		}
	}
}
