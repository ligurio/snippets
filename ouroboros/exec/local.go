package exec

import (
	"errors"
	log "github.com/Sirupsen/logrus"
	"github.com/mattn/go-shellwords"
	"os/exec"
)

var (
	shParser      = shellwords.NewParser()
	ErrCmdIsEmpty = errors.New("Job Command is empty.")
)

func init() {
	shParser.ParseEnv = true
	shParser.ParseBacktick = true
}

func RunCmd(command string) error {
	args, err := shParser.Parse(command)
	if err != nil {
		return err
	}

	if len(args) == 0 {
		return ErrCmdIsEmpty
	}

	cmd := exec.Command(args[0], args[1:]...)
	log.Infof("Local execution")
	return cmd.Run()
}
