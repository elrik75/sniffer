package clock

import (
	"time"
	"sync"
)

type clock struct {
	time time.Time
	mtx  *sync.Mutex
}

func (c *clock) Init() {
	c.mtx = new(sync.Mutex)
}

func (c *clock) Get() (time.Time) {
//	c.mtx.Lock()
//	defer c.mtx.Unlock()
	return c.time
}

func (c *clock) Set(t time.Time) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.time = t
}

// Global singleton
var Clock *clock

func InitClock() {
	Clock = new(clock)
	Clock.Init()
}