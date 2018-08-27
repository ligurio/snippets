package exec

import (
	log "github.com/Sirupsen/logrus"
	"os"
	"os/exec"
)

func exec_command(program string, args ...string) {
	cmd := exec.Command(program, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Infof("%v\n", err)
	}
}

func execVagrant(vagrantfile string) {
	exec_command("vagrant", "ssh")
	log.Infof("Vagrant execution")
}
