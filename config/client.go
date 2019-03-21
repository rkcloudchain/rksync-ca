package config

import (
	"github.com/rkcloudchain/rksync-ca/api"
)

// ClientConfig is the rksync-ca client's config
type ClientConfig struct {
	URL      string
	TLS      ClientTLSConfig
	Debug    bool
	LogLevel string
	CAName   string
	CSR      api.CSRInfo
}
