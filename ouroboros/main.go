package main

import (
	log "github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"

	"github.com/ligurio/ouroboros/api"
	"github.com/ligurio/ouroboros/job"
	"runtime"
)

const (
	httpPort     = "8000"
	httpAddress  = "0.0.0.0"
	defaultOwner = "sergeyb@openvz.org"
)

func main() {

	runtime.GOMAXPROCS(runtime.NumCPU())

	app := cli.NewApp()
	app.Name = "Ouroboros"
	app.Usage = "Modern Continuous Integration scheduler without pain"
	app.Version = "0.01"

	// jobs for debug
	newJob1 := &job.Job{Name: "Job1", Command: "ls -1", Schedule: "*/10 * * * * *", Hosts: []string{"s101.qa.sw.ru", "s102.qa.sw.ru"}}
	newJob2 := &job.Job{Name: "Job2", Command: "ls /root", Schedule: "*/5 * * * * *", Hosts: []string{"s105.qa.sw.ru"}}

	targets := job.NewHostPool()
	cache := job.NewJobCache()

	newJob1.Init(cache, targets)
	newJob2.Init(cache, targets)

	connectionString := httpAddress + ":" + httpPort
	log.Infof("Starting server on port %s...", connectionString)
	log.Fatal(api.StartServer(connectionString, cache, defaultOwner))
}
