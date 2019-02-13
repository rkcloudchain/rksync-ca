package server

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/pkg/errors"
	"github.com/rkcloudchain/courier-ca/attrmgr"
	"github.com/rkcloudchain/courier-ca/config"
	"github.com/rkcloudchain/courier-ca/util"
)

const (
	certificateError = "Invalid certificate in file"
)

// CA represents a certificate authority which signs, issues and revokes certificates
type CA struct {
	// The home directory for the CA
	HomeDir string
	// The CA's configuration
	Config *config.CAConfig
	// The signer used for enrollment
	enrollSigner signer.Signer
	// The attribute manager
	attrMgr *attrmgr.Mgr
	// The crypto service provider (BCCSP)
	csp bccsp.BCCSP
}

// Initialize the CA's key material
func (ca *CA) initKeyMaterial(renew bool) error {
	log.Debug("Initialize key material")

	err := ca.makeFileNamesAbsolute()
	if err != nil {
		return err
	}

	keyFile := ca.Config.CA.Keyfile
	certFile := ca.Config.CA.Certfile

	if !renew {
		keyFileExists := util.FileExists(keyFile)
		certFileExists := util.FileExists(certFile)
		if keyFileExists && certFileExists {
			log.Info("The CA key and certificate files already exists")
			log.Infof("Key file location: %s", keyFile)
			log.Infof("Certificate file location: %s", certFile)
			err = ca.validateCertAndKey(certFile, keyFile)
			if err != nil {
				return errors.WithMessage(err, "Validation of certificate and key failed")
			}

			ca.Config.CSR.CN, err = ca.loadCNFromEnrollmentInfo(certFile)
			if err != nil {
				return err
			}
			return nil
		}

		if certFileExists {
			_, _, _, err = util.GetSingerFromCertFile(certFile, ca.csp)
			if err != nil {
				return errors.WithMessage(err, fmt.Sprintf("Failed to find private key for certificate in '%s'", certFile))
			}

			log.Info("The CA key and certificate already exists")
			log.Infof("The key is stored by BCCSP provider '%s'", ca.Config.CSP.ProviderName)
			log.Infof("The certificate is at: %s", certFile)

			ca.Config.CSR.CN, err = ca.loadCNFromEnrollmentInfo(certFile)
			if err != nil {
				return errors.WithMessage(err, fmt.Sprintf("Failed to get CN for certificate in '%s'", certFile))
			}
			return nil
		}
		log.Warningf("The specified CA certificate file %s does not exists", certFile)
	}

}

// Get the CA certificate for this CA
func (ca *CA) getCACert() (cert []byte, err error) {
	if ca.Config.Intermediate.ParentServer.URL != "" {
		log.Debugf("Getting CA cert; parent server URL is %s", util.GetMaskedURL(ca.Config.Intermediate.ParentServer.URL))
		clientCfg := ca.Config.Client
		if clientCfg == nil {
			clientCfg = &config.ClientConfig{}
		}
		clientCfg.TLS = ca.Config.Intermediate.TLS

	}
}

// Load CN from existing enrollment information
func (ca *CA) loadCNFromEnrollmentInfo(certFile string) (string, error) {
	log.Debug("Loading CN from existing enrollment information")

	cert, err := ioutil.ReadFile(certFile)
	if err != nil {
		log.Debugf("No cert found at %s", certFile)
		return "", err
	}

	name, err := util.GetEnrollmentIDFromPEM(cert)
	if err != nil {
		return "", err
	}
	return name, nil
}

// Performs checks on the provided CA cert to make sure it's valid
func (ca *CA) validateCertAndKey(certFile string, keyFile string) error {
	log.Debug("Validating the CA certificate and key")
	var err error
	var certPEM []byte

	certPEM, err = ioutil.ReadFile(certFile)
	if err != nil {
		return errors.Wrapf(err, certificateError+" '%s'", certFile)
	}

	cert, err := util.GetX509CertificateFromPEM(certPEM)
	if err != nil {
		return errors.WithMessage(err, fmt.Sprintf(certificateError+" '%s'", certFile))
	}

	if err = validateDates(cert); err != nil {
		return errors.WithMessage(err, fmt.Sprintf(certificateError+" '%s'", certFile))
	}
	if err = validateUsage(cert, ca.Config.CA.Name); err != nil {
		return errors.WithMessage(err, fmt.Sprintf(certificateError+" '%s'", certFile))
	}
	if err = validateIsCA(cert); err != nil {
		return errors.WithMessage(err, fmt.Sprintf(certificateError+" '%s'", certFile))
	}
	if err = validateKeyType(cert); err != nil {
		return errors.WithMessage(err, fmt.Sprintf(certificateError+" '%s'", certFile))
	}
	if err = validateKeySize(cert); err != nil {
		return errors.WithMessage(err, fmt.Sprintf(certificateError+" '%s'", certFile))
	}
	if err = validateMatchingKeys(cert, keyFile); err != nil {
		return errors.WithMessage(err, fmt.Sprintf("Invalid certificate and/or key in files '%s' and '%s'", certFile, keyFile))
	}
	log.Debug("Validation of CA certificate and key successful")
	return nil
}

// Make all file names in the CA config absolute
func (ca *CA) makeFileNamesAbsolute() error {
	log.Debug("Making CA file names absolute")

	fields := []*string{&ca.Config.CA.Certfile, &ca.Config.CA.Keyfile, &ca.Config.CA.Chainfile}
	return util.MakeFileNamesAbsolute(fields, ca.HomeDir)
}

func validateDates(cert *x509.Certificate) error {
	log.Debug("Check CA certificate for valid dates")

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

func validateUsage(cert *x509.Certificate, caname string) error {
	log.Debug("Check CA certificate for valid usages")

	if cert.KeyUsage == 0 {
		return errors.New("No usage specified for certificate")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("The 'cert sign' key usage is required")
	}
	if !canSignCRL(cert) {
		log.Warningf("The CA certificate for the CA '%s' does not have 'crl sign' key usage, so the CA will not be able to generate a CRL", caname)
	}
	return nil
}

func validateIsCA(cert *x509.Certificate) error {
	log.Debug("Check CA certificate for valid IsCA value")

	if !cert.IsCA {
		return errors.New("Certificate not configured to be used for CA")
	}

	return nil
}

func validateKeyType(cert *x509.Certificate) error {
	log.Debug("Check that key type is supported")

	switch cert.PublicKey.(type) {
	case *dsa.PublicKey:
		return errors.New("Unsupported key type: DSA")
	}

	return nil
}

func validateKeySize(cert *x509.Certificate) error {
	log.Debug("Check that key size is of appropriate length")

	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		size := cert.PublicKey.(*rsa.PublicKey).N.BitLen()
		if size < 2048 {
			return errors.New("Key size is less than 2048 bits")
		}
	}

	return nil
}

func validateMatchingKeys(cert *x509.Certificate, keyFile string) error {
	log.Debug("Check that public key and private key match")

	keyPEM, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return err
	}

	pubKey := cert.PublicKey
	switch pubKey.(type) {
	case *rsa.PublicKey:
		privKey, err := util.GetRSAPrivateKey(keyPEM)
		if err != nil {
			return err
		}

		if privKey.PublicKey.N.Cmp(pubKey.(*rsa.PublicKey).N) != 0 {
			return errors.New("Public key and private key do not match")
		}
	case *ecdsa.PrivateKey:
		privKey, err := util.GetECPrivateKey(keyPEM)
		if err != nil {
			return err
		}

		if privKey.PublicKey.X.Cmp(pubKey.(*ecdsa.PublicKey).X) != 0 {
			return errors.New("Public key and private key do not match")
		}
	}

	return nil
}

func canSignCRL(cert *x509.Certificate) bool {
	return cert.KeyUsage&x509.KeyUsageCRLSign != 0
}
