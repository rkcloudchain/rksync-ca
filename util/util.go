package util

import (
	"os"

	"github.com/pkg/errors"
	"github.com/rkcloudchain/courier-ca/config"
	"github.com/spf13/viper"
)

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
		serverCfg := cfg.(*config.ServerConfig)
		err = vp.Unmarshal(&serverCfg.CACfg)
		if err != nil {
			return errors.Wrapf(err, "Incorrect format in file '%s'", configFile)
		}
	}
	return nil
}

// FileExists checks to see if a file exists.
func FileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}
