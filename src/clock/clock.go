package clock

import (
	"time"
	"sync"
	"math"
//	"fmt"
)

var (
	DUMPPERIOD = time.Duration(60 * math.Pow(10, 9)) // 60s
)

type clock struct {
	time      time.Time
	last_dump time.Time
	mtx       *sync.Mutex
	DumpChan chan bool
}

func (c *clock) Init() {
	c.mtx = new(sync.Mutex)
	c.DumpChan = make(chan bool)
}

func (c *clock) Get() (time.Time) {
//	c.mtx.Lock()
//	defer c.mtx.Unlock()
	return c.time
}

func (c *clock) GetForDump() int64 {
	time := c.Get().Unix()
	return time - time % int64(DUMPPERIOD.Seconds())
}

func (c *clock) Set(t time.Time) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	c.time = t
	if c.last_dump.IsZero() {
			c.last_dump = t
	} else if t.Sub(c.last_dump) > DUMPPERIOD {
		c.DumpChan <- true
		c.last_dump = t
	}
}

// Global singleton
var Clock *clock

func InitClock() {
	Clock = new(clock)
	Clock.Init()
}