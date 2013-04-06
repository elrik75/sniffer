package data

import (
//    "fmt"
    "strings"
    "sync"
    "time"

    // internal
    "clock"
)

// PACKET
type IPacket interface {
    Show() string
    GetTime() time.Time
}

// KEY
type IKey interface {
    Show() string
    Serial() ISerial
    Number() uint16
}
type ISerial interface {}


// STAT
type IStat interface {
    Show() string
    CSVRow() string
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
    LOCKNUM uint16 = 1
)

// MAP
type PMap struct {
    once       sync.Once
    mtx        *sync.Mutex
    StatsChans map[ISerial]*StatsChans
    timeout    time.Duration
}

func (pmap *PMap) GetLock() *sync.Mutex {
    return pmap.mtx
}

func (pmap *PMap) Init(timeout time.Duration) {
    pmap.once.Do(func() {
        pmap.StatsChans = make(map[ISerial]*StatsChans, 2000)
        pmap.mtx = new(sync.Mutex)
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
    lock := pmap.GetLock()
    lock.Lock()
    defer lock.Unlock()
    pmap.unsafeSet(key, stats)
}

func (pmap *PMap) Get(key IKey) *StatsChans {
    lock := pmap.GetLock()
    lock.Lock()
    defer lock.Unlock()
    return pmap.unsafeGet(key)
}

func (pmap *PMap) Delete(key IKey) {
    // lock := pmap.GetLock()
    // lock.Lock()
    // defer lock.Unlock()
    delete(pmap.StatsChans, key.Serial())
}

func (pmap *PMap) InitValue(key IKey) (bool, *StatsChans) {
    //key is a pointer
    lock := pmap.GetLock()
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
    var lasttime time.Time

MAIN:
    for {
        select {

        // the handlar is init with a first input
        case packet := <-chans.Inputs:
            // timoutcheck.Stop()
            // timoutcheck = time.NewTicker(pmap.timeout)
            stats.AppendStat(key, packet)
            lasttime = packet.GetTime()

        case control := <-chans.Control:
            // order is important
            if strings.Contains(control, "<dump>") {
                chans.Results <- stats.Copy()
            }
            if strings.Contains(control, "<timeout>") {
                if clock.Clock.Get().After(lasttime.Add(time.Duration(pmap.timeout))) {
					pmap.Delete(key)
					break MAIN
				}
            }
            if strings.Contains(control, "<kill>") {
                pmap.Delete(key)
                break MAIN
            }
            if strings.Contains(control, "<reset>") {
                stats.Reset()
            }
        }
    }
}
