package config

import (
	cfsslcfg "github.com/cloudflare/cfssl/config"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/pkg/errors"
	"github.com/rkcloudchain/courier-ca/api"
	"github.com/spf13/viper"
)

// ServerConfig is the courier-ca server's configuration
type ServerConfig struct {
	// Listening port for the server
	Port int
	// Bind address for the server
	Address string
	// Enables  debug logging
	Debug bool
	// Sets the logging level on the server
	LogLevel string
	// CACfg is the default CA's config
	CACfg CAConfig
	// TLS for the server's listening endpoint
	TLS ServerTLSConfig
}

// ServerTLSConfig defines key material for a TLS server
type ServerTLSConfig struct {
	Enabled    bool
	CertFile   string
	KeyFile    string
	ClientAuth ClientAuth
}

// ClientTLSConfig defines the key material for a TLS client
type ClientTLSConfig struct {
	Enabled   bool
	CertFiles []string
	Client    KeyCertFiles
}

// KeyCertFiles defines the files need for client on TLS
type KeyCertFiles struct {
	KeyFile  string
	CertFile string
}

// ClientAuth defines the key material needed to verify client certificates
type ClientAuth struct {
	Type      string
	CertFiles []string
}

// CAConfig is the CA instance's configuration
type CAConfig struct {
	Version      string
	CA           CAInfo
	Signing      *cfsslcfg.Signing
	CSR          api.CSRInfo
	Intermediate IntermediateCA
	Registry     CAConfigRegistry
	CRL          CRLConfig
	CSP          *factory.FactoryOpts
	Client       *ClientConfig
}

// CAConfigRegistry is the registry part of the server's config
type CAConfigRegistry struct {
	MaxEnrollments int
}

// CRLConfig contains configuration options used by the gencrl request handler
type CRLConfig struct{}

// ParentServer contains URL for the parent server and the name of CA inside
// the server to connect to
type ParentServer struct {
	URL    string
	CAName string
}

// IntermediateCA contains parent server information, TLS configuration, and
// enrollment request for an intermediate CA
type IntermediateCA struct {
	ParentServer ParentServer
	TLS          ClientTLSConfig
}

// CAInfo is the CA information on a courier-ca
type CAInfo struct {
	Name      string
	Keyfile   string
	Certfile  string
	Chainfile string
}

// UnmarshalConfig unmarshals a configuration file
func UnmarshalConfig(cfg interface{}, vp *viper.Viper, configFile string, server bool) error {
	vp.SetConfigFile(configFile)
	err := vp.ReadInConfig()
	if err != nil {
		return errors.Wrapf(err, "Failed to read config file '%s'", configFile)
	}

	err = vp.Unmarshal(cfg)
	if err != nil {
		return errors.Wrapf(err, "Incorrect format in file '%s'", configFile)
	}

	if server {
		serverCfg := cfg.(*ServerConfig)
		err = vp.Unmarshal(&serverCfg.CACfg)
		if err != nil {
			return errors.Wrapf(err, "Incorrect format in file '%s'", configFile)
		}
	}
	return nil
}
