package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/revoke"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"github.com/rkcloudchain/rksync-ca/config"
	caerrors "github.com/rkcloudchain/rksync-ca/errors"
	"github.com/rkcloudchain/rksync-ca/metadata"
	"github.com/rkcloudchain/rksync-ca/util"
)

const (
	defaultClientAuth = "noclientcert"
	apiPathPrefix     = "/api/v1/"
)

// endpoint is an endpoint method on a server
type endpoint func(s *Server, resp http.ResponseWriter, rep *http.Request) (interface{}, error)

var endpoints map[string]endpoint

// Server is the rksync-ca server
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
	// An error which occurs when serving
	serverError error
}

// Init initializes a rksync-ca server
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

// Start the rksync-ca server
func (s *Server) Start() (err error) {
	log.Infof("Starting server in home directory: %s", s.HomeDir)

	s.serverError = nil

	if s.listener != nil {
		return errors.New("server is already started")
	}

	err = s.init(false)
	if err != nil {
		err2 := s.CA.closeDB()
		if err2 != nil {
			log.Errorf("Close DB failed: %s", err2)
		}
		return err
	}

	s.registerHandlers()

	err = s.listenAndServe()
	if err != nil {
		err2 := s.CA.closeDB()
		if err2 != nil {
			log.Errorf("Close DB failed: %s", err2)
		}
		return err
	}
	return nil
}

// Stop the server
func (s *Server) Stop() error {
	err := s.closeListener()
	if err != nil {
		return err
	}

	log.Debugf("Stop: successful stop on port %d", s.Config.Port)

	err = s.CA.closeDB()
	if err != nil {
		log.Errorf("Close DB failed: %s", err)
	}
	return nil
}

// Starting listening and serving
func (s *Server) listenAndServe() (err error) {
	var listener net.Listener
	var clientAuth tls.ClientAuthType
	var ok bool

	c := s.Config
	if c.Address == "" {
		c.Address = config.DefaultServerAddr
	}
	if c.Port == 0 {
		c.Port = config.DefaultServerPort
	}
	addr := net.JoinHostPort(c.Address, strconv.Itoa(c.Port))
	var addrStr string

	if c.TLS.Enabled {
		log.Debug("TLS is enabled")
		addrStr = fmt.Sprintf("https://%s", addr)

		if !util.FileExists(c.TLS.KeyFile) {
			return errors.Errorf("File specified by 'tls.keyfile' does not exists: %s", c.TLS.KeyFile)
		} else if !util.FileExists(c.TLS.CertFile) {
			return errors.Errorf("File specified by 'tls.certfile' does not exists: %s", c.TLS.CertFile)
		}
		log.Debugf("TLS Certificate: %s, TLS Key: %s", c.TLS.CertFile, c.TLS.KeyFile)

		cer, err := util.LoadX509KeyPair(c.TLS.CertFile, c.TLS.KeyFile, s.csp)
		if err != nil {
			return err
		}

		if c.TLS.ClientAuth.Type == "" {
			c.TLS.ClientAuth.Type = defaultClientAuth
		}
		log.Debugf("Client authentication type requested: %s", c.TLS.ClientAuth.Type)

		authType := strings.ToLower(c.TLS.ClientAuth.Type)
		if clientAuth, ok = clientAuthTypes[authType]; !ok {
			return errors.New("Invalid client auth type provided")
		}

		var certPool *x509.CertPool
		if authType != defaultClientAuth {
			certPool, err = LoadPEMCertPool(c.TLS.ClientAuth.CertFiles)
			if err != nil {
				return err
			}
		}

		config := &tls.Config{
			Certificates: []tls.Certificate{*cer},
			ClientAuth:   clientAuth,
			ClientCAs:    certPool,
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
			CipherSuites: config.DefaultCipherSuites,
		}

		listener, err = tls.Listen("tcp", addr, config)
		if err != nil {
			return errors.Wrapf(err, "TLS listen failed for %s", addrStr)
		}
	} else {
		addrStr = fmt.Sprintf("http://%s", addr)
		listener, err = net.Listen("tcp", addr)
		if err != nil {
			return errors.Wrapf(err, "TCP listen failed for %s", addrStr)
		}
	}
	s.listener = listener
	log.Infof("Listening on %s", addrStr)
	return s.serve()
}

func (s *Server) serve() error {
	listener := s.listener
	if listener == nil {
		return nil
	}
	s.serverError = http.Serve(listener, s.mux)
	log.Errorf("Server has stopped serving: %s", s.serverError)
	s.closeListener()
	err := s.CA.closeDB()
	if err != nil {
		log.Errorf("Close DB failed: %s", err)
	}
	return s.serverError
}

// Closes the listening endpoint
func (s *Server) closeListener() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	port := s.Config.Port
	if s.listener == nil {
		msg := fmt.Sprintf("Stop: listener was already closed on port %d", port)
		log.Debug(msg)
		return errors.New(msg)
	}
	err := s.listener.Close()
	s.listener = nil
	if err != nil {
		log.Debugf("Stop: failed to close listener on port %d: %s", port, err)
		return err
	}
	log.Debugf("Stop: successfully closed listener on port %d", port)
	return nil
}

func (s *Server) registerHandlers() {
	s.mux = mux.NewRouter()
	s.registerHandler("enroll", enrollHandler, http.MethodPost)
}

func (s *Server) registerHandler(path string, e endpoint, methods ...string) {
	bound := func(resp http.ResponseWriter, req *http.Request) (interface{}, error) {
		return e(s, resp, req)
	}
	s.mux.Handle("/"+path, s.wrap(bound)).Methods(methods...)
	s.mux.Handle(apiPathPrefix+path, s.wrap(bound)).Methods(methods...)
}

func (s *Server) wrap(handler func(http.ResponseWriter, *http.Request) (interface{}, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Debugf("Received request for %s", r.URL.String())
		resp, err := handler(w, r)
		he := s.getHTTPErr(err)

		w.Header().Set("Connection", "Keep-Alive")
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Length", "0")
		} else {
			w.Header().Set("Transfer-Encoding", "chunked")
			w.Header().Set("Content-Type", "application/json")
		}

		if he != nil {
			w.WriteHeader(he.GetStatusCode())
			log.Infof(`%s %s %s %d %d "%s"`, r.RemoteAddr, r.Method, r.URL, he.GetStatusCode(), he.GetLocalCode(), he.GetLocalMsg())
		} else {
			w.WriteHeader(http.StatusOK)
			log.Infof(`%s %s %s %d 0 "OK"`, r.RemoteAddr, r.Method, r.URL, http.StatusOK)
		}

		if r.Method != http.MethodHead {
			w.Write([]byte(`{"result":`))
			if resp != nil {
				s.writeJSON(resp, w)
			} else {
				w.Write([]byte(`""`))
			}

			w.Write([]byte(`,"errors":[`))
			if he != nil {
				rm := &api.ResponseMessage{Code: he.GetRemoteCode(), Message: he.GetRemoteMsg()}
				s.writeJSON(rm, w)
			}
			w.Write([]byte(`],"messages":[],"success":`))
			if he != nil {
				w.Write([]byte(`false}`))
			} else {
				w.Write([]byte(`true}`))
			}
		}
	}
}

func (s *Server) writeJSON(obj interface{}, w http.ResponseWriter) {
	enc := json.NewEncoder(w)
	err := enc.Encode(obj)
	if err != nil {
		log.Errorf("Failed encoding response to JSON: %s", err)
	}
}

func (s *Server) getHTTPErr(err error) *caerrors.HTTPErr {
	if err == nil {
		return nil
	}
	type causer interface {
		Cause() error
	}

	curErr := err
	for curErr != nil {
		switch curErr.(type) {
		case *caerrors.HTTPErr:
			return curErr.(*caerrors.HTTPErr)
		case causer:
			curErr = curErr.(causer).Cause()
		default:
			return caerrors.CreateHTTPErr(500, caerrors.ErrUnknown, err.Error())
		}
	}

	return caerrors.CreateHTTPErr(500, caerrors.ErrUnknown, "nil error")
}

// GetCA returns the CA instance
func (s *Server) GetCA() *CA {
	return &s.CA
}
