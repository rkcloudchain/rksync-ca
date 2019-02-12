package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/pkg/errors"
	"github.com/rkcloudchain/courier-ca/metadata"
	"github.com/rkcloudchain/courier-ca/util"
)

const (
	cmdName      = "courier-ca"
	longName     = "CloucChain Courier Certificate Authority Server"
	envVarPrefix = "COURIER_CA"
)

const (
	defaultCfgTemplate = `
# Version of config file
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

registry:
  # Maximum number of times a password/secret can be reused for enrollment
  # (default: -1, which means there is no limit)
  maxenrollments: -1

  # Contains identity infomation
  identities:
	- name: <<<ADMIN>>>
	  pass: <<<ADMINPW>>>

#############################################################################
#  Database section
#  Supported types are: "postgres", and "mysql".
#  The datasource value depends on the type.
#############################################################################
db:
  type: mysql
  datasource:
`
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

	err = util.UnmarshalConfig(s.cfg, s.v, s.cfgFileName, true)
	if err != nil {
		return err
	}

	return nil
}

func (s *ServerCmd) createDefaultConfigFile() error {
	var user, pass string
	up := s.v.GetString("boot")
	if up == "" {
		return errors.New("The '-b user:pass' option is required")
	}
	ups := strings.Split(up, ":")
	if len(ups) < 2 {
		return errors.Errorf("The value '%s' on the command line is missing a colon separator", up)
	}
	if len(ups) > 2 {
		ups = []string{ups[0], strings.Join(ups[1:], ":")}
	}
	user = ups[0]
	pass = ups[1]
	if len(user) > 1024 {
		return errors.Errorf("The identity name must be less than 1024 characters: '%s'", user)
	}
	if len(pass) == 0 {
		return errors.New("An empty password in the '-b user:pass' option is not permitted")
	}

	cfg := strings.Replace(defaultCfgTemplate, "<<<VERSION>>>", metadata.Version, 1)
	cfg = strings.Replace(cfg, "<<<ADMIN>>>", user, 1)
	cfg = strings.Replace(cfg, "<<<ADMINPW>>>", pass, 1)

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
	envs := []string{"COURIER_CA_SERVER_HOME", "COURIER_CA_HOME", "CA_CFG_PATH"}
	for _, env := range envs {
		envVal := os.Getenv(env)
		if envVal != "" {
			home = envVal
			break
		}
	}
	return filepath.Join(home, fname)
}
