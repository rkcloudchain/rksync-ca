package config

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/pkg/errors"
	"github.com/rkcloudchain/courier-ca/util"
)

// DefaultCipherSuites is a set of strong TLS cipher suites
var DefaultCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
}

// AbsTLSClient makes TLS client files absolute
func AbsTLSClient(cfg *ClientTLSConfig, configDir string) error {
	var err error

	for i := 0; i < len(cfg.CertFiles); i++ {
		cfg.CertFiles[i], err = util.MakeFileAbs(cfg.CertFiles[i], configDir)
		if err != nil {
			return err
		}
	}

	cfg.Client.CertFile, err = util.MakeFileAbs(cfg.Client.CertFile, configDir)
	if err != nil {
		return err
	}

	cfg.Client.KeyFile, err = util.MakeFileAbs(cfg.Client.KeyFile, configDir)
	if err != nil {
		return err
	}

	return nil
}

// GetClientTLSConfig creates a tls.Config oject from certs and roots
func GetClientTLSConfig(cfg *ClientTLSConfig, csp bccsp.BCCSP) (*tls.Config, error) {
	var certs []tls.Certificate

	if csp == nil {
		csp = factory.GetDefault()
	}

	log.Debugf("CA Files: %+v", cfg.CertFiles)
	log.Debugf("Client Cert File: %s", cfg.Client.CertFile)
	log.Debugf("Client Key File: %s", cfg.Client.KeyFile)

	if cfg.Client.CertFile != "" {
		err := checkCertDates(cfg.Client.CertFile)
		if err != nil {
			return nil, err
		}

		clientCert, err := util.LoadX509KeyPair(cfg.Client.CertFile, cfg.Client.KeyFile, csp)
		if err != nil {
			return nil, err
		}

		certs = append(certs, *clientCert)
	} else {
		log.Debug("Client TLS certificate and/or key file not provided")
	}

	rootCAPool := x509.NewCertPool()
	if len(cfg.CertFiles) == 0 {
		return nil, errors.New("No trusted root certificate for TLS were provided")
	}

	for _, cacert := range cfg.CertFiles {
		caCert, err := ioutil.ReadFile(cacert)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to read '%s'", cacert)
		}
		ok := rootCAPool.AppendCertsFromPEM(caCert)
		if !ok {
			return nil, errors.Errorf("Failed to process certificate from file %s", cacert)
		}
	}

	config := &tls.Config{
		Certificates: certs,
		RootCAs:      rootCAPool,
	}
	return config, nil
}

func checkCertDates(certFile string) error {
	log.Debug("Check client TLS certificate for valid dates")
	certPEM, err := ioutil.ReadFile(certFile)
	if err != nil {
		return errors.Wrapf(err, "Failed to read file '%s'", certFile)
	}

	cert, err := util.GetX509CertificateFromPEM(certPEM)
	if err != nil {
		return err
	}

	notAfter := cert.NotAfter
	currentTime := time.Now().UTC()

	if currentTime.After(notAfter) {
		return errors.New("Certificate provided has expired")
	}

	notBefore := cert.NotBefore
	if currentTime.Before(notBefore) {
		return errors.New("Certificate provided not valid until later date")
	}

	return nil
}

// AbsTLSServer makes TLS server files absolute
func AbsTLSServer(cfg *ServerTLSConfig, configDir string) error {
	var err error

	for i := 0; i < len(cfg.ClientAuth.CertFiles); i++ {
		cfg.ClientAuth.CertFiles[i], err = util.MakeFileAbs(cfg.ClientAuth.CertFiles[i], configDir)
		if err != nil {
			return err
		}
	}

	cfg.CertFile, err = util.MakeFileAbs(cfg.CertFile, configDir)
	if err != nil {
		return err
	}

	cfg.KeyFile, err = util.MakeFileAbs(cfg.KeyFile, configDir)
	if err != nil {
		return err
	}

	return nil
}
