package job

import (
	"errors"
	"sync"
	//log "github.com/Sirupsen/logrus"
)

var (
	ErrHostDoesntExist = errors.New("The host you requested does not exist.")
	ErrHostsAreBusy    = errors.New("All appropriate hosts are busy.")
)

type Host struct {
	Hostname string
	Busy     bool
	Lock     sync.RWMutex
}

type HostsMap struct {
	Hosts map[string]*Host
}

type HostPool struct {
	hosts *HostsMap
	Lock  sync.RWMutex
}

func NewHostsMap() *HostsMap {
	return &HostsMap{
		Hosts: map[string]*Host{},
	}
}

func NewHostPool() *HostPool {
	return &HostPool{
		hosts: NewHostsMap(),
		Lock:  sync.RWMutex{},
	}
}

func (c *HostPool) GetAll() *HostsMap {
	return c.hosts
}

// Add new host with given hostname
func (c *HostPool) Set(h string) error {
	c.Lock.Lock()
	defer c.Lock.Unlock()

	if h == "" {
		return nil
	}

	c.hosts.Hosts[h] = &Host{Hostname: h, Busy: false}
	return nil
}

// Find host by hostname
func (c *HostPool) Get(h string) (*Host, error) {
	c.Lock.Lock()
	defer c.Lock.Unlock()

	host := c.hosts.Hosts[h]
	if host == nil {
		return nil, ErrHostDoesntExist
	}

	return host, nil
}

func (h *Host) MarkAsBusy() error {
	h.Lock.Lock()
	h.Busy = true
	h.Lock.Unlock()
	return nil
}

func (h *Host) Release() error {
	h.Lock.Lock()
	h.Busy = false
	h.Lock.Unlock()
	return nil
}

// Find a free suitable host and reserve it
func (c *HostPool) Take(j *Job) (*Host, error) {

	for _, h := range j.Hosts {
		hwnode, _ := c.Get(h)
		if !hwnode.Busy {
			hwnode.MarkAsBusy()
			return hwnode, nil
		}
	}
	return nil, ErrHostsAreBusy
}
