package client

import (
	"os"
	"path/filepath"
	"testing"

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
			MSPDir: "msp",
		},
	}
	resp, err := c.Register(&api.RegistrationRequest{
		Name: "xqlun6",
	})

	assert.NoError(t, err)
	assert.NotEmpty(t, resp.Secret)
}

func TestEnroll(t *testing.T) {
	
}