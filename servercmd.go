package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/rkcloudchain/courier-ca/config"
	"github.com/rkcloudchain/courier-ca/metadata"
	"github.com/rkcloudchain/courier-ca/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	version = "version"
)

// ServerCmd encapsulates cobra command that provides command line interface
// for the Courier CA server
type ServerCmd struct {
	name          string
	rootCmd       *cobra.Command
	v             *viper.Viper
	cfgFileName   string
	homeDirectory string
	cfg           *config.ServerConfig
}

// NewCommand returns new ServerCmd ready for running
func NewCommand(name string) *ServerCmd {
	s := &ServerCmd{
		name: name,
		v:    viper.New(),
	}
	s.init()
	return s
}

// Execute runs this ServerCmd
func (s *ServerCmd) Execute() error {
	return s.rootCmd.Execute()
}

func (s *ServerCmd) init() {
	// root command
	rootCmd := &cobra.Command{
		Use:   cmdName,
		Short: longName,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			err := s.configInit()
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true
			if s.v.GetBool("debug") {
				log.Level = log.LevelDebug
			}
			return nil
		},
	}
	s.rootCmd = rootCmd

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Prints Courier CA Server version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(metadata.GetVersionInfo(cmdName))
		},
	}
	s.rootCmd.AddCommand(versionCmd)
	s.registerFlags()
}

// registers command flags with viper
func (s *ServerCmd) registerFlags() {
	cfg := defaultConfigFile()

	s.v.SetEnvPrefix(envVarPrefix)
	s.v.SetEnvKeyReplacer(strings.NewReplacer(",", "_"))

	pflags := s.rootCmd.PersistentFlags()
	pflags.StringVarP(&s.cfgFileName, "config", "c", "", "Configuration file")
	pflags.MarkHidden("config")

	pflags.StringVarP(&s.homeDirectory, "home", "H", "", fmt.Sprintf("Server's home directory (default \"%s\")", filepath.Dir(cfg)))
	util.FlagString(s.v, pflags, "boot", "b", "", "The user:pass for bootstrap admin which is required to build default config file")
}

// Configuration file is not required for some commands like version
func (s *ServerCmd) configRequired() bool {
	return s.name != version
}
