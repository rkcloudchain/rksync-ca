package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/pkg/errors"
	"github.com/rkcloudchain/rksync-ca/config"
	"github.com/rkcloudchain/rksync-ca/metadata"
	"github.com/rkcloudchain/rksync-ca/util"
)

const (
	cmdName      = "rksync-ca"
	shortName    = "rksync-ca server"
	longName     = "CloucChain rksync Certificate Authority Server"
	envVarPrefix = "RKSYNC_CA"
)

const (
	defaultCfgTemplate = `# Version of config file
version: <<<VERSION>>>

# Server's listening port (default:8054)
port: 8054

#############################################################################
#  TLS section for the server's listening port
#
#  The following types are supported for client authentication: NoClientCert,
#  RequestClientCert, RequireAnyClientCert, VerifyClientCertIfGiven,
#  and RequireAndVerifyClientCert.
#
#  Certfiles is a list of root certificate authorities that the server uses
#  when verifying client certificates.
#############################################################################
tls:
  # Enable TLS (default: false)
  enabled: false
  # TLS for the server's listening port
  certfile:
  keyfile:
  clientauth:
    type: noclientcert
    certfiles:

#############################################################################
#  The CA section contains information related to the Certificate Authority
#  including the name of the CA, which should be unique for all members
#  of a blockchain network.  It also includes the key and certificate files
#  used when issuing enrollment certificates (ECerts) and transaction
#  certificates (TCerts).
#  The chainfile (if it exists) contains the certificate chain which
#  should be trusted for this CA, where the 1st in the chain is always the
#  root CA certificate.
#############################################################################
ca:
  # Name of this CA
  name:
  # Key file (is only used to import a private key into BCCSP)
  keyfile:
  # Certificate file (default: ca-cert.pem)
  certfile:
  # Chain file
  chainfile:

#############################################################################
#  The gencrl REST endpoint is used to generate a CRL that contains revoked
#  certificates. This section contains configuration options that are used
#  during gencrl request processing.
#############################################################################
crl:
  # Specifies expiration for the generated CRL. The number of hours
  # specified by this property is added to the UTC time, the resulting time
  # is used to set the 'Next Update' date of the CRL.
  expiry: 24h

#############################################################################
# Intermediate CA section
#
# The relationship between servers and CAs is as follows:
#   1) A single server process may contain or function as one or more CAs.
#      This is configured by the "Multi CA section" above.
#   2) Each CA is either a root CA or an intermediate CA.
#   3) Each intermediate CA has a parent CA which is either a root CA or another intermediate CA.
#
# This section pertains to configuration of #2 and #3.
# If the "intermediate.parentserver.url" property is set,
# then this is an intermediate CA with the specified parent
# CA.
#
# parentserver section
#    url - The URL of the parent server
#    caname - Name of the CA to enroll within the server
#
# tls section for secure socket connection
#   certfiles - PEM-encoded list of trusted root certificate files
#   client:
#     certfile - PEM-encoded certificate file for when client authentication
#     is enabled on server
#     keyfile - PEM-encoded key file for when client authentication
#     is enabled on server
#############################################################################
intermediate:
  parentserver:
    url:
    caname:

  tls:
    certfiles:
    client:
      certfile:
      keyfile:

#############################################################################
#  The registry section
#############################################################################
registry:
  # Maximum number of times a password/secret can be reused for enrollment
  # (default: -1, which means there is no limit)
  maxenrollments: -1

#############################################################################
#  Database section
#  Supported types are: "postgres", and "mysql".
#  The datasource value depends on the type.
#############################################################################
db:
  type: <<<DATABASETYPE>>>
  datasource: <<<DATASOURCE>>>
`
)

var (
	extraArgsError = "Unrecognized arguments found: %v\n\n%s"
)

// Initialize config
func (s *ServerCmd) configInit() (err error) {
	if !s.configRequired() {
		return nil
	}

	s.cfgFileName, s.homeDirectory, err = validateAndReturnAbsConf(s.cfgFileName, s.homeDirectory, cmdName)
	if err != nil {
		return err
	}

	s.v.AutomaticEnv()
	logLevel := s.v.GetString("loglevel")
	setLogLevel(logLevel)

	log.Debugf("Home directory: %s", s.homeDirectory)

	if !util.FileExists(s.cfgFileName) {
		err = s.createDefaultConfigFile()
		if err != nil {
			return errors.WithMessage(err, "Failed to create default configuration file")
		}
		log.Infof("Created default configuration file at %s", s.cfgFileName)
	} else {
		log.Infof("Configuration file location: %s", s.cfgFileName)
	}

	err = config.UnmarshalConfig(s.cfg, s.v, s.cfgFileName, true)
	if err != nil {
		return err
	}

	return nil
}

func (s *ServerCmd) createDefaultConfigFile() error {
	dtype := s.v.GetString("dbtype")
	if dtype == "" {
		return errors.New("The '-dt' option is required (for example '-dt mysql')")
	}

	ds := s.v.GetString("datasource")
	if ds == "" {
		return errors.New("The '-ds datasource' option is required")
	}

	cfg := strings.Replace(defaultCfgTemplate, "<<<VERSION>>>", metadata.Version, 1)
	cfg = strings.Replace(cfg, "<<<DATABASETYPE>>>", dtype, 1)
	cfg = strings.Replace(cfg, "<<<DATASOURCE>>>", ds, 1)
	cfgDir := filepath.Dir(s.cfgFileName)
	err := os.MkdirAll(cfgDir, 0755)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(s.cfgFileName, []byte(cfg), 0644)
}

func setLogLevel(logLevel string) {
	switch strings.ToUpper(logLevel) {
	case "INFO":
		log.Level = log.LevelInfo
	case "WARNING":
		log.Level = log.LevelWarning
	case "DEBUG":
		log.Level = log.LevelDebug
	case "ERROR":
		log.Level = log.LevelError
	case "CRITICAL":
		log.Level = log.LevelCritical
	case "FATAL":
		log.Level = log.LevelFatal
	default:
		log.Level = log.LevelInfo
	}
}

// checks to see that there are no conflicts between the configuration file path and home directory.
// If no conflicts, returns back the absolute path for the configuration file and home directory.
func validateAndReturnAbsConf(configFilePath, homeDir, cmdName string) (string, string, error) {
	var err error
	var homeDirSet bool
	var configFileSet bool

	defaultConfig := defaultConfigFile()
	if configFilePath == "" {
		configFilePath = defaultConfig
	} else {
		configFileSet = true
	}

	if homeDir == "" {
		homeDir = filepath.Dir(defaultConfig)
	} else {
		homeDirSet = true
	}

	homeDir, err = filepath.Abs(homeDir)
	if err != nil {
		return "", "", errors.Wrap(err, "Failed to get full path of config file")
	}
	homeDir = strings.TrimRight(homeDir, string(os.PathSeparator))

	if configFileSet && homeDirSet {
		log.Warning("Using both --config and --home CLI flags; --config will take precedence")
	}

	if configFileSet {
		configFilePath, err = filepath.Abs(configFilePath)
		if err != nil {
			return "", "", errors.Wrap(err, "Failed to get full path of configuration file")
		}
		return configFilePath, filepath.Dir(configFilePath), nil
	}

	configFile := filepath.Join(homeDir, filepath.Base(defaultConfig))
	return configFile, homeDir, nil
}

func defaultConfigFile() string {
	fname := fmt.Sprintf("%s-config.yaml", cmdName)
	home := "."
	envs := []string{"RKSYNC_CA_SERVER_HOME", "RKSYNC_CA_HOME", "CA_CFG_PATH"}
	for _, env := range envs {
		envVal := os.Getenv(env)
		if envVal != "" {
			home = envVal
			break
		}
	}
	return filepath.Join(home, fname)
}
