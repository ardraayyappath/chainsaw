package ssh

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

// RemoteConnector holds an authenticated SSH connection to a single target machine.
type RemoteConnector struct {
	client *ssh.Client
	target string // "host:port", for logging and error context
}

// NewRemoteConnector dials the target over SSH using a private key file.
// Password authentication is not supported — key auth only.
func NewRemoteConnector(host string, port int, user, keyPath string) (*RemoteConnector, error) {
	signer, err := loadPrivateKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("load private key %q: %w", keyPath, err)
	}

	cfg := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		// HostKeyCallback is set to InsecureIgnoreHostKey to avoid requiring
		// a known_hosts file during research use. For production hardening,
		// replace with ssh.FixedHostKey or a known_hosts-backed callback.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
	}

	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	client, err := ssh.Dial("tcp", target, cfg)
	if err != nil {
		return nil, fmt.Errorf("ssh dial %s: %w", target, err)
	}

	return &RemoteConnector{
		client: client,
		target: target,
	}, nil
}

// Close terminates the underlying SSH connection.
func (c *RemoteConnector) Close() error {
	if err := c.client.Close(); err != nil {
		return fmt.Errorf("close ssh connection to %s: %w", c.target, err)
	}
	return nil
}

// Target returns the "host:port" string for this connection, useful for log messages.
func (c *RemoteConnector) Target() string {
	return c.target
}

// loadPrivateKey reads a PEM-encoded private key from disk and returns a Signer.
func loadPrivateKey(path string) (ssh.Signer, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return signer, nil
}
