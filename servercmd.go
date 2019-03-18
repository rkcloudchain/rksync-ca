package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/pkg/errors"
	"github.com/rkcloudchain/rksync-ca/config"
	"github.com/rkcloudchain/rksync-ca/metadata"
	"github.com/rkcloudchain/rksync-ca/server"
	"github.com/rkcloudchain/rksync-ca/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	version = "version"
)

// ServerCmd encapsulates cobra command that provides command line interface
// for the rksync CA server
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
		Short: "Prints rksync CA Server version",
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

	s.cfg = &config.ServerConfig{}
	err := util.RegisterFlags(s.v, pflags, s.cfg, nil)
	if err != nil {
		panic(err)
	}

	tags := map[string]string{
		"help.csr.cn":           "The common name field of the certificate signing request to a parent rksync-ca-server",
		"help.csr.serialnumber": "The serial number in a certificate signing request t oa parent rksync-ca-server",
		"help.csr.hosts":        "A list of host names in a certificate signing request to a parent rksync-ca-server",
	}
	err = util.RegisterFlags(s.v, pflags, &s.cfg.CACfg, tags)
	if err != nil {
		panic(err)
	}
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
