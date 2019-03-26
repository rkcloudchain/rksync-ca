package config

import (
	"os"
	"testing"

	"github.com/rkcloudchain/rksync-ca/util"
	"github.com/stretchr/testify/assert"
)

const (
	configDir = "../testdata"
)

func TestGetClientTLSConfig(t *testing.T) {
	cfg := &ClientTLSConfig{
		CertFiles: []string{"root.pem"},
		Client: KeyCertFiles{
			KeyFile:  "tls-client.key.pem",
			CertFile: "tls-client.cert.pem",
		},
	}

	err := AbsTLSClient(cfg, configDir)
	assert.NoError(t, err)

	csp, err := util.InitCCCSP("csp")
	assert.NoError(t, err)
	defer os.RemoveAll("csp")

	_, err = GetClientTLSConfig(cfg, csp)
	assert.NoError(t, err)
}

func TestAbsServerTLSConfig(t *testing.T) {
	cfg := &ServerTLSConfig{
		KeyFile:  "tls-client.key.pem",
		CertFile: "tls-client.cert.pem",
		ClientAuth: ClientAuth{
			CertFiles: []string{"root.pem"},
		},
	}

	err := AbsTLSServer(cfg, configDir)
	assert.NoError(t, err)
}

func TestGetClientTLSConfigInvalidArgs(t *testing.T) {
	csp, err := util.InitCCCSP("csp")
	assert.NoError(t, err)
	defer os.RemoveAll("csp")

	cfg := &ClientTLSConfig{
		CertFiles: []string{"root.pem"},
		Client: KeyCertFiles{
			KeyFile:  "no-tls-client.key.pem",
			CertFile: "no-tls-client.cert.pem",
		},
	}

	_, err = GetClientTLSConfig(cfg, csp)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no such file or directory")

	cfg = &ClientTLSConfig{
		CertFiles: []string{},
		Client: KeyCertFiles{
			KeyFile:  "tls-client.key.pem",
			CertFile: "tls-client.cert.pem",
		},
	}
	AbsTLSClient(cfg, configDir)

	_, err = GetClientTLSConfig(cfg, csp)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "No trusted root certificate for TLS were provided")

	cfg = &ClientTLSConfig{
		CertFiles: []string{"no-root.pem"},
		Client: KeyCertFiles{
			KeyFile:  "tls-client.key.pem",
			CertFile: "tls-client.cert.pem",
		},
	}
	AbsTLSClient(cfg, configDir)

	_, err = GetClientTLSConfig(cfg, csp)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no such file or directory")
}
