package client

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rkcloudchain/rksync-ca/config"
	"github.com/stretchr/testify/assert"
)

func TestClientInit(t *testing.T) {
	c := &Client{}
	c.Config = &config.ClientConfig{}
	tmpDir := os.TempDir()
	c.HomeDir = tmpDir

	defer func() {
		err := os.RemoveAll(filepath.Join(tmpDir, "csp"))
		assert.NoError(t, err)
	}()

	err := c.Init()
	assert.NoError(t, err)
	assert.True(t, c.initialized)

	fi, err := os.Stat(filepath.Join(tmpDir, "csp", "signcerts"))
	assert.NoError(t, err)
	assert.True(t, fi.IsDir())

	fi, err = os.Stat(filepath.Join(tmpDir, "csp", "cacerts"))
	assert.NoError(t, err)
	assert.True(t, fi.IsDir())

	fi, err = os.Stat(filepath.Join(tmpDir, "csp", "keystore"))
	assert.NoError(t, err)
	assert.True(t, fi.IsDir())
}
