package config

import (
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/rkcloudchain/rksync-ca/api"
)

// ClientConfig is the rksync-ca client's config
type ClientConfig struct {
	URL      string
	MSPDir   string
	TLS      ClientTLSConfig
	Debug    bool
	LogLevel string
	CSP      *factory.FactoryOpts
	CAName   string
	CSR      api.CSRInfo
}
