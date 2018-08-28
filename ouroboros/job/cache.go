package job

import (
	"errors"
	"sync"
)

var (
	ErrJobDoesntExist = errors.New("The job you requested does not exist")
)

type JobsMap struct {
	Jobs map[string]*Job
	Lock sync.RWMutex
}

func NewJobsMap() *JobsMap {
	return &JobsMap{
		Jobs: map[string]*Job{},
		Lock: sync.RWMutex{},
	}
}

type JobCache struct {
	// Jobs is a map from Job id's to pointers to the jobs.
	// Used as the main "data store" within this cache implementation.
	jobs *JobsMap
}

func NewJobCache() *JobCache {
	return &JobCache{
		jobs: NewJobsMap(),
	}
}

func (c *JobCache) Start() {

	// FIXME

	/*
		for _, j := range allJobs {
			j.StartWaiting(c)
			c.Set(j)
		}
	*/
}

func (c *JobCache) Get(id string) (*Job, error) {
	c.jobs.Lock.RLock()
	defer c.jobs.Lock.RUnlock()

	j := c.jobs.Jobs[id]
	if j == nil {
		return nil, ErrJobDoesntExist
	}

	return j, nil
}

func (c *JobCache) GetAll() *JobsMap {
	return c.jobs
}

func (c *JobCache) Set(j *Job) error {
	c.jobs.Lock.Lock()
	defer c.jobs.Lock.Unlock()

	if j == nil {
		return nil
	}

	c.jobs.Jobs[j.Id] = j
	return nil
}

func (c *JobCache) Delete(id string) error {
	c.jobs.Lock.Lock()
	defer c.jobs.Lock.Unlock()

	j := c.jobs.Jobs[id]
	if j == nil {
		return ErrJobDoesntExist
	}

	j.Disable()

	//go j.DeleteFromParentJobs(c)

	// Remove itself from dependent jobs as a parent job
	// and possibly delete child jobs if they don't have any other parents.
	//go j.DeleteFromDependentJobs(c)

	delete(c.jobs.Jobs, id)

	return nil
}
