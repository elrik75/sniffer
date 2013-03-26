package data

import (
//	"fmt"
	"strings"
	"sync"
	"time"

	// internal
	"clock"
)

// PACKET
type IPacket interface {
	Show()    string
	GetTime() time.Time
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
	LOCKNUM uint16 = 128
)

// MAP
type PMap struct {
	once       sync.Once
	mtx        map[uint16]*sync.Mutex
	StatsChans map[string]*StatsChans
	timeout    time.Duration
}

func (pmap *PMap) GetLock(key IKey) *sync.Mutex {
	return pmap.mtx[key.Number()]
}

func (pmap *PMap) Init(timeout time.Duration) {
	pmap.once.Do(func() {
		pmap.StatsChans = make(map[string]*StatsChans, 2000)
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
	pmap.unsafeSet(key, stats)
}

func (pmap *PMap) Get(key IKey) *StatsChans {
	lock := pmap.GetLock(key)
	lock.Lock()
	defer lock.Unlock()
	return pmap.unsafeGet(key)
}

func (pmap *PMap) Delete(key IKey) {
	lock := pmap.GetLock(key)
	lock.Lock()
	defer lock.Unlock()
	delete(pmap.StatsChans, key.Serial())
}

func (pmap *PMap) InitValue(key IKey) (bool, *StatsChans) {
	//key is a pointer
	lock := pmap.GetLock(key)
	lock.Lock()
	defer lock.Unlock()

	var stats_chans *StatsChans
	stats_chans = pmap.unsafeGet(key)

	if stats_chans != nil {
		return false, stats_chans
	}
	//fmt.Println(key.Show())

	data_chan := make(chan IPacket, 8)
	result_chan := make(chan IStat, 8)
	control_chan := make(chan string)
	stats_chans = &StatsChans{data_chan, result_chan, control_chan}
	pmap.unsafeSet(key, stats_chans)

	return true, stats_chans
}

func Handler(pmap *PMap, key IKey, stats IStat) {

	chans := pmap.Get(key)
	// check if timeout
	//fmt.Println(pmap.timeout)
	timoutcheck := time.NewTicker(pmap.timeout/2)
	var lasttime time.Time

MAIN:
	for {
		select {

		case <-timoutcheck.C:
			if clock.Clock.Get().After(lasttime.Add(time.Duration(pmap.timeout))) {
				pmap.Delete(key)
				//fmt.Print(".")
				break MAIN
			}

		// the handlar is init with a first input
		case packet := <-chans.Inputs:
			timoutcheck.Stop()
			timoutcheck = time.NewTicker(pmap.timeout)
			stats.AppendStat(key, packet)
			lasttime = packet.GetTime()

		case control := <-chans.Control:
			if strings.Contains(control, "<dump>") {
				chans.Results <- stats.Copy()
			}
			if strings.Contains(control, "<reset>") {
				stats.Reset()
			}
			if strings.Contains(control, "<timeout>") {
				;
			}
			if strings.Contains(control, "<kill>") {
				// fmt.Println("KILL ", key.Show())
				pmap.Delete(key)
				break MAIN
			}

		}
	}
	close(chans.Control) 
}
