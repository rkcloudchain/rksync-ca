package server

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	cfcfg "github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/rkcloudchain/rksync-ca/api"
	"github.com/rkcloudchain/rksync-ca/client"
	"github.com/rkcloudchain/rksync-ca/config"
	"github.com/stretchr/testify/assert"
)

const (
	rootDir     = "rootDir"
	rootPort    = 10054
	testdataDir = "../testdata"
)

func TestServerInit(t *testing.T) {
	srv := getRootServer(t)
	assert.NotNil(t, srv)

	err := srv.Init(false)
	assert.NoError(t, err)

	defer func() {
		err = os.RemoveAll(rootDir)
		assert.NoError(t, err)
	}()

	err = srv.Init(false)
	assert.NoError(t, err)

	err = srv.Init(true)
	assert.NoError(t, err)
}

func TestServerStart(t *testing.T) {
	srv := getRootServer(t)
	assert.NotNil(t, srv)

	err := srv.Start()
	assert.NoError(t, err)

	defer func() {
		err = srv.Stop()
		assert.NoError(t, err)

		err = os.RemoveAll(rootDir)
		assert.NoError(t, err)

		err = os.RemoveAll(filepath.Join(testdataDir, "csp"))
		assert.NoError(t, err)
	}()

	err = srv.Start()
	assert.Error(t, err)

	c := getRootClient()
	rr, err := c.Register(&api.RegistrationRequest{
		Name:       "user1",
		Attributes: []api.Attribute{api.Attribute{Name: "attr1", Value: "value1"}},
	})
	assert.NoError(t, err)
	assert.NotEmpty(t, rr.Secret)

	erresp, err := c.Enroll(&api.EnrollmentRequest{
		Name:   "user1",
		Secret: rr.Secret,
		CSR: &api.CSRInfo{CN: "Rockontrol", Names: []csr.Name{
			csr.Name{C: "CN", ST: "Sichuan", L: "Chengdu", O: "CloudChain", OU: "Dep"},
		}},
	}, true)

	assert.NoError(t, err)
	user1 := erresp.Identity
	cert := user1.GetECert().GetX509Cert()
	assert.NotNil(t, cert)
}

func getRootServer(t *testing.T) *Server {
	os.RemoveAll(rootDir)
	profiles := map[string]*cfcfg.SigningProfile{
		"tls": &cfcfg.SigningProfile{
			Usage:        []string{"signing", "key encipherment", "server auth", "client auth", "key agreement"},
			ExpiryString: "8760h",
		},
		"ca": &cfcfg.SigningProfile{
			Usage:        []string{"cert sign", "crl sign"},
			ExpiryString: "8760h",
			CAConstraint: cfcfg.CAConstraint{
				IsCA:       true,
				MaxPathLen: 0,
			},
		},
	}

	defaultProfile := &cfcfg.SigningProfile{
		Usage:        []string{"cert sign"},
		ExpiryString: "8760h",
	}

	srv := &Server{
		Config: &config.ServerConfig{
			Port:  rootPort,
			Debug: true,
		},
		CA: CA{
			Config: &config.CAConfig{
				Registry: config.CAConfigRegistry{
					MaxEnrollments: -1,
				},
				Signing: &cfcfg.Signing{
					Profiles: profiles,
					Default:  defaultProfile,
				},
			},
		},
		HomeDir: rootDir,
	}
	return srv
}

func getRootClient() *client.Client {
	return &client.Client{
		Config:  &config.ClientConfig{URL: fmt.Sprintf("http://localhost:%d", rootPort)},
		HomeDir: testdataDir,
	}
}
