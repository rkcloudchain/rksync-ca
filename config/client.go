package config

import (
	"github.com/hyperledger/fabric/bccsp/factory"
)

// ClientConfig is the courier-ca client's config
type ClientConfig struct {
	URL      string
	MSPDir   string
	TLS      ClientTLSConfig
	Debug    bool
	LogLevel string
	CSP      *factory.FactoryOpts
}
