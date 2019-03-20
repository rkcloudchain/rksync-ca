package client

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/cfssl/csr"
	"github.com/rkcloudchain/rksync-ca/api"
	"github.com/rkcloudchain/rksync-ca/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegister(t *testing.T) {
	userHome, err := os.UserHomeDir()
	require.NoError(t, err)

	home := filepath.Join(userHome, ".rksync-ca-client")
	c := &Client{
		HomeDir: home,
		Config: &config.ClientConfig{
			URL:    "http://localhost:8054",
			CSPDir: "msp",
		},
	}
	resp, err := c.Register(&api.RegistrationRequest{
		Name: "xqlun7",
	})

	assert.NoError(t, err)
	assert.NotEmpty(t, resp.Secret)
	t.Log(resp.Secret)
}

func TestEnroll(t *testing.T) {
	userHome, err := os.UserHomeDir()
	require.NoError(t, err)

	home := filepath.Join(userHome, ".rksync-ca-client")
	c := &Client{
		HomeDir: home,
		Config: &config.ClientConfig{
			URL:    "http://localhost:8054",
			CSPDir: "msp",
		},
	}

	_, err = c.Enroll(&api.EnrollmentRequest{
		Name:   "xqlun7",
		Secret: "OoQULAhRyUIt",
		CSR: &api.CSRInfo{
			CN: "Rockontrol",
			Names: []csr.Name{
				csr.Name{C: "CN", ST: "Sichuan", L: "Chengdu", O: "Dep"},
			},
		},
	})
	assert.NoError(t, err)
}
