package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/pkg/errors"
	"github.com/rkcloudchain/courier-ca/config"
	"github.com/rkcloudchain/courier-ca/metadata"
	"github.com/rkcloudchain/courier-ca/server"
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

	initCmd := &cobra.Command{
		Use:   "init",
		Short: fmt.Sprintf("Initialize the %s", shortName),
		Long:  "Generate the key material needed by the server if it doesn't already exist",
	}
	initCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return errors.Errorf(extraArgsError, args, initCmd.UsageString())
		}
		err := s.getServer().Init(false)
		if err != nil {
			util.Fatal("Initialization failure: %s", err)
		}
		log.Info("Initialization was successful")
		return nil
	}
	s.rootCmd.AddCommand(initCmd)

	startCmd := &cobra.Command{
		Use:   "start",
		Short: fmt.Sprintf("Start the %s", shortName),
	}
	startCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return errors.Errorf(extraArgsError, args, startCmd.UsageString())
		}
		err := s.getServer().Start()
		if err != nil {
			return err
		}
		return nil
	}
	s.rootCmd.AddCommand(startCmd)

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
	util.FlagString(s.v, pflags, "dbtype", "dt", "", "The database type is required to build default config file")
	util.FlagString(s.v, pflags, "datasource", "ds", "", "The database datasource is required to build default config file")

	s.cfg = &config.ServerConfig{}
}

// Configuration file is not required for some commands like version
func (s *ServerCmd) configRequired() bool {
	return s.name != version
}

// getServer returns a server.Server for the init and start commands
func (s *ServerCmd) getServer() *server.Server {
	return &server.Server{
		HomeDir: s.homeDirectory,
		Config:  s.cfg,
		CA: server.CA{
			Config: &s.cfg.CACfg,
		},
	}
}
