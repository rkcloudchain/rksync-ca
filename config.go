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
#  Signing section
#
#  The "default" subsection is used to sign enrollment certificates;
#  the default expiration ("expiry" field) is "8760h", which is 1 year in hours.
#
#  The "ca" profile subsection is used to sign intermediate CA certificates;
#  the default expiration ("expiry" field) is "43800h" which is 5 years in hours.
#  Note that "isca" is true, meaning that it issues a CA certificate.
#  A maxpathlen of 0 means that the intermediate CA cannot issue other
#  intermediate CA certificates, though it can still issue end entity certificates.
#  (See RFC 5280, section 4.2.1.9)
#
#  The "tls" profile subsection is used to sign TLS certificate requests;
#  the default expiration ("expiry" field) is "8760h", which is 1 year in hours.
#############################################################################
signing:
  default:
    usage:
      - digital signature
    expiry: 8760h
  profiles:
    ca:
      usage:
        - cert sign
        - crl sign
      expiry: 43800h
      caconstraint:
        isca: true
        maxpathlen: 0
    tls:
      usage:
        - signing
        - key encipherment
        - server auth
        - client auth
        - key agreement
      expiry: 8760h

###########################################################################
#  Certificate Signing Request (CSR) section.
#  This controls the creation of the root CA certificate.
#  The expiration for the root CA certificate is configured with the
#  "ca.expiry" field below, whose default value is "131400h" which is
#  15 years in hours.
#  The pathlength field is used to limit CA certificate hierarchy as described
#  in section 4.2.1.9 of RFC 5280.
#  Examples:
#  1) No pathlength value means no limit is requested.
#  2) pathlength == 1 means a limit of 1 is requested which is the default for
#     a root CA.  This means the root CA can issue intermediate CA certificates,
#     but these intermediate CAs may not in turn issue other CA certificates
#     though they can still issue end entity certificates.
#  3) pathlength == 0 means a limit of 0 is requested;
#     this is the default for an intermediate CA, which means it can not issue
#     CA certificates though it can still issue end entity certificates.
###########################################################################
csr:
  cn: <<<COMMONNAME>>>
  keyrequest:
    algo: ecdsa
    size: 256
  names:
    - C: CN
      ST: "Sichuan"
      L: "Chengdu"
      O: "Rockontrol"
      OU: "rksync-ca"
  hosts:
    - <<<MYHOST>>>
    - localhost
  ca:
    expiry: 131400h
    pathlength: <<<PATHLENGTH>>>

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

	pl := "csr.ca.pathlength"
	if s.v.IsSet(pl) && s.v.GetInt(pl) == 0 {
		s.cfg.CACfg.CSR.CA.PathLenZero = true
	}

	pl = "signing.profiles.ca.caconstraint.maxpathlen"
	if s.v.IsSet(pl) && s.v.GetInt(pl) == 0 {
		s.cfg.CACfg.Signing.Profiles["ca"].CAConstraint.MaxPathLenZero = true
	}

	return nil
}

func (s *ServerCmd) createDefaultConfigFile() error {
	dtype := s.v.GetString("db.type")
	if dtype == "" {
		return errors.New("The '--db.type' option is required (for example '-db.type mysql')")
	}

	ds := s.v.GetString("db.datasource")
	if ds == "" {
		return errors.New("The '--db.datasource' option is required")
	}

	var myhost string
	var err error
	myhost, err = os.Hostname()
	if err != nil {
		return err
	}

	cfg := strings.Replace(defaultCfgTemplate, "<<<VERSION>>>", metadata.Version, 1)
	cfg = strings.Replace(cfg, "<<<DATABASETYPE>>>", dtype, 1)
	cfg = strings.Replace(cfg, "<<<DATASOURCE>>>", ds, 1)
	cfg = strings.Replace(cfg, "<<<MYHOST>>>", myhost, 1)
	purl := s.v.GetString("intermediate.parentserver.url")
	if purl == "" {
		cfg = strings.Replace(cfg, "<<<COMMONNAME>>>", "rksync-ca-server", 1)
		cfg = strings.Replace(cfg, "<<<PATHLENGTH>>>", "1", 1)
	} else {
		cfg = strings.Replace(cfg, "<<<COMMONNAME>>>", "", 1)
		cfg = strings.Replace(cfg, "<<<PATHLENGTH>>>", "0", 1)
	}

	cfgDir := filepath.Dir(s.cfgFileName)
	err = os.MkdirAll(cfgDir, 0755)
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
