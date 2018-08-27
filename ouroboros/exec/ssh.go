package exec

import (
	"bytes"
	log "github.com/Sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"net"
	"os"
)

const (
	sshPort = "22"
)

func SSHAgent() ssh.AuthMethod {
	if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		return ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers)
	}
	return nil
}

func CommandSSH(command string, hostname string) (*bytes.Buffer, error) {

	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{SSHAgent()},
	}

	conn, err := ssh.Dial("tcp", hostname+":"+sshPort, config)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Run(command)

	log.Infof(hostname, stdoutBuf.String())
	return &stdoutBuf, nil
}
