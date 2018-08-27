package exec

import (
	"bytes"
	log "github.com/Sirupsen/logrus"
	"github.com/fsouza/go-dockerclient"
)

func CommandDocker() error {
	// Use environment variables to obtain required information
	// about Docker daemon
	// See https://docs.docker.com/machine/reference/env/
	client, err := docker.NewClientFromEnv()
	if err != nil {
		log.Println(err)
	}

	info, err := client.Info()
	if err != nil {
		log.Println(err)
	}

	log.Infof("Docker Endpoint: %s\n", client.Endpoint())
	log.Infof("Kernel Version: %s\n", info.KernelVersion)
	log.Infof("Operating System: %s\n", info.OperatingSystem)

	// Run command inside image prepared with Dockerfile
	outputbuf := bytes.NewBuffer(nil)
	buildOpts := docker.BuildImageOptions{
		Name:                "ouroboros",
		OutputStream:        outputbuf,
		ForceRmTmpContainer: true,
		Remote:              "https://raw.githubusercontent.com/sekka1/Dockerfile-Ubuntu-Gnome/master/Dockerfile",
	}

	if err := client.BuildImage(buildOpts); err != nil {
		log.Fatal(err)
	}

	client.InspectImage("ouroboros")
	return nil
}
