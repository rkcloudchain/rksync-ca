package server

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/revoke"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"github.com/rkcloudchain/courier-ca/config"
	"github.com/rkcloudchain/courier-ca/metadata"
	"github.com/rkcloudchain/courier-ca/util"
)

// Server is the courier-ca server
type Server struct {
	// The home directory for the server
	HomeDir string
	// The server's configuration
	Config *config.ServerConfig
	// The server mux
	mux *mux.Router
	// The current listener for this server
	listener net.Listener
	// Server's default CA
	CA
}

// Init initializes a courier-ca server
func (s *Server) Init(renew bool) (err error) {
	err = s.init(renew)
	err2 := s.CA.closeDB()
	if err2 != nil {
		log.Errorf("Close DB failed: %s", err2)
	}
	return err
}

// Initializes the server leaving the DB open
func (s *Server) init(renew bool) (err error) {
	serverVersion := metadata.GetVersion()
	log.Infof("Server Version: %s", serverVersion)

	err = s.initConfig()
	if err != nil {
		return err
	}

	err = s.initDefaultCA(renew)
	if err != nil {
		return err
	}

	return nil
}

func (s *Server) initConfig() (err error) {
	if s.HomeDir == "" {
		s.HomeDir, err = os.Getwd()
		if err != nil {
			return errors.Wrap(err, "Failed to get server's home directory")
		}
	}

	absoluteHomeDir, err := filepath.Abs(s.HomeDir)
	if err != nil {
		return errors.Errorf("Failed to make server's home directory path absolute: %s", err)
	}
	s.HomeDir = absoluteHomeDir

	if s.Config == nil {
		s.Config = new(config.ServerConfig)
	}
	revoke.SetCRLFetcher(s.fetchCRL)
	s.makeFileNamesAbsolute()

	return nil
}

func (s *Server) initDefaultCA(renew bool) error {
	log.Debugf("Initializing default CA in directory %s", s.HomeDir)
	ca := &s.CA
	err := initCA(ca, s.HomeDir, s.CA.Config, renew)
	if err != nil {
		return err
	}
	log.Infof("Home directory for default CA: %s", ca.HomeDir)
	return nil
}

// Read the CRL from body of http response
func (s *Server) fetchCRL(r io.Reader) ([]byte, error) {
	crlSizeLimit := s.Config.CRLSizeLimit
	log.Debugf("CRL size limit is %d bytes", crlSizeLimit)

	crl := make([]byte, crlSizeLimit)
	crl, err := util.Read(r, crl)
	if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("Error reading CRL with max buffer size of %d", crlSizeLimit))
	}

	return crl, nil
}

// Make all file names in the config absolute
func (s *Server) makeFileNamesAbsolute() error {
	log.Debug("Making server filenames abosulte")
	return config.AbsTLSServer(&s.Config.TLS, s.HomeDir)
}

// Start the courier-ca server
func (s *Server) Start() (err error) {
	return nil
}
