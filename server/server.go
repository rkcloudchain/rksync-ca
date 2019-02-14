package server

import (
	"net"

	"github.com/cloudflare/cfssl/log"
	"github.com/gorilla/mux"
	"github.com/rkcloudchain/courier-ca/config"
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

func (s *Server) initDefaultCA(renew bool) error {
	log.Debugf("Initializing default CA in directory %s", s.HomeDir)
	// ca := &s.CA
	return nil
}

// initCA will initialize the passed in pointer to a CA struct
func initCA(ca *CA, homeDir string, config *config.CAConfig, server *Server, renew bool) error {
	ca.HomeDir = homeDir
	ca.Config = config
	return nil
}
