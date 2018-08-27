package job

import (
	"bytes"
	"errors"
	"sync"
	"time"

	"github.com/robfig/cron"

	log "github.com/Sirupsen/logrus"
	"github.com/ligurio/ouroboros/exec"
	"github.com/nu7hatch/gouuid"
)

var (
	ErrInvalidJob    = errors.New("Invalid Job. Job's must contain a Name and a Command field")
	ErrJobAlreadyRun = errors.New("This jobs is already started.")
	ErrJobDisabled   = errors.New("Job cannot run, as it is disabled")
)

const (
	currentDir = "/var/ouroboros/"
)

type Job struct {
	Name string `json:"name"`
	Id   string `json:"id"`

	// Command to run
	// e.g. "python tests/zdtm.py"
	Command string `json:"command"`

	// Email of the owner of this job
	// e.g. "contacts@openvz.org"
	Owner string `json:"owner"`

	// Is this job disabled?
	Disabled bool `json:"disabled"`

	// Jobs that are dependent upon this one will be run after this job runs.
	DependentJobs []string `json:"dependent_jobs"`

	// List of ids of jobs that this job is dependent upon.
	ParentJobs []string `json:"parent_jobs"`

	// Hosts suitable for running our Job
	Hosts []string `json:"hosts"`

	// CRON Expression Format
	// https://godoc.org/github.com/robfig/cron#hdr-CRON_Expression_Format
	Schedule string `json:"schedule"`

	CronJob *cron.Cron

	// True when Job is running
	running bool

	// Meta data about successful and failed runs.
	Metadata Metadata `json:"metadata"`

	// Collection of Job Stats
	Stats []*JobStat `json:"stats"`

	lock sync.RWMutex
}

// JobStat is used to store metrics about a specific Job.Run()
type JobStat struct {
	JobId             string        `json:"job_id"`
	RanAt             time.Time     `json:"ran_at"`
	NumberOfRetries   uint          `json:"number_of_retries"`
	Success           bool          `json:"success"`
	ExecutionDuration time.Duration `json:"execution_duration"`
}

type Metadata struct {
	SuccessCount     uint      `json:"success_count"`
	LastSuccess      time.Time `json:"last_success"`
	ErrorCount       uint      `json:"error_count"`
	LastError        time.Time `json:"last_error"`
	LastAttemptedRun time.Time `json:"last_attempted_run"`
}

// Perform various checks to validate new job
func (j *Job) Sanitize() error {
	j.lock.Lock()
	defer j.lock.Unlock()

	if j.Name == "" || j.Command == "" {
		log.Errorf(ErrInvalidJob.Error())
		return ErrInvalidJob
	}

	return nil
}

// Initialize a new Job
func (j *Job) Init(cache *JobCache, targets *HostPool) error {

	err := j.Sanitize()
	if err != nil {
		return err
	}

	j.lock.Lock()
	defer j.lock.Unlock()

	// Add remote targets to our host pool
	for _, h := range j.Hosts {
		targets.Set(h)
	}

	j.CronJob = cron.New()
	j.CronJob.AddFunc(j.Schedule, func() { j.Run(targets) })

	u4, err := uuid.NewV4()
	if err != nil {
		log.Errorf("Error occured when generating uuid: %s", err)
		return err
	}
	j.Id = u4.String()

	err = cache.Set(j)
	if err != nil {
		return err
	}

	/*
		if len(j.ParentJobs) != 0 {
			// Add new job to parent jobs
			for _, p := range j.ParentJobs {
				parentJob, err := cache.Get(p)
				if err != nil {
					return err
				}
				parentJob.DependentJobs = append(parentJob.DependentJobs, j.Id)
			}

			return nil
		}
	*/

	if j.Schedule == "" {
		// TODO: If schedule is empty, its a one-off job.
	}

	j.lock.Unlock()
	j.CronJob.Start()
	j.lock.Lock()

	return nil
}

// Disable stops the job from running by stopping its CronJob
// and also sets Job.Disabled to true.
func (j *Job) Disable() {
	j.lock.Lock()
	defer j.lock.Unlock()

	j.CronJob.Stop()
	j.Disabled = true
}

func (j *Job) Enable() {
	j.lock.Lock()
	defer j.lock.Unlock()

	j.CronJob.Start()
	j.Disabled = false
}

func (j *Job) StopTimer() {
	j.lock.Lock()
	defer j.lock.Unlock()

	j.CronJob.Stop()
}

func (j *Job) Run(targets *HostPool) error {
	j.lock.RLock()
	defer j.lock.RUnlock()

	if j.running {
		log.Infof("[Job: %s] It's already running.", j.Name)
		return ErrJobAlreadyRun
	}

	var (
		hwnode *Host
		err    error
		result *bytes.Buffer
	)
	if j.Hosts == nil {
		j.running = true
		err = exec.RunCmd(j.Command)
	} else {
		hwnode, err = targets.Take(j)
		if err != nil {
			return errors.New("There is no suitable target.")
		}
		j.running = true
		result, err = exec.CommandSSH(j.Command, hwnode.Hostname)
		hwnode.Release()
	}

	j.running = false
	j.Metadata.LastAttemptedRun = time.Now()

	if err != nil {
		j.Metadata.ErrorCount++
		j.Metadata.LastError = time.Now()
		log.Infof("[Job: %s] FAIL '%s', '%s'", j.Name, j.Command, hwnode.Hostname)
		log.Println(err)
		return err
	} else {
		j.Metadata.SuccessCount++
		j.Metadata.LastSuccess = time.Now()
		log.Infof("[Job: %s] SUCCESS '%s', '%s' - %s", j.Name, j.Command, hwnode.Hostname, result.String())
		return nil
	}
}
