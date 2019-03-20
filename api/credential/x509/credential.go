package x509

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/cloudflare/cfssl/log"
	"github.com/pkg/errors"
	"github.com/rkcloudchain/cccsp"
	"github.com/rkcloudchain/rksync-ca/api/credential"
	"github.com/rkcloudchain/rksync-ca/util"
)

const (
	// CredType is the string that represents X509 credential type
	CredType = "X509"
)

// Client represents a client that will load/store an credential
type Client interface {
	NewX509Identity(name string, creds []credential.Credential) Identity
	GetCSP() cccsp.CCCSP
}

// Identity represents an identity
type Identity interface {
	GetECert() *Signer
	GetName() string
	GetX509Credential() credential.Credential
	Store() error
	Revoke(req *credential.RevocationRequest) (*credential.RevocationResponse, error)
}

// NewCredential is constructor for X509 Credential
func NewCredential(certFile, keyFile string, c Client) *Credential {
	return &Credential{
		c, certFile, keyFile, nil,
	}
}

// Credential represents a X509 credential. Implements Credential interface
type Credential struct {
	client   Client
	certFile string
	keyFile  string
	val      *Signer
}

// Type returns X509
func (cred *Credential) Type() string {
	return CredType
}

// Val returns *Signer associated with this X509 credential
func (cred *Credential) Val() (interface{}, error) {
	if cred.val == nil {
		return nil, errors.New("X509 Credential value is not set")
	}
	return cred.val, nil
}

// EnrollmentID returns enrollment ID of this X509 credential
func (cred *Credential) EnrollmentID() (string, error) {
	if cred.val == nil {
		return "", errors.New("X509 Credential value is not set")
	}
	return cred.val.GetName(), nil
}

// SetVal sets *Signer for this X509 credential
func (cred *Credential) SetVal(val interface{}) error {
	s, ok := val.(*Signer)
	if !ok {
		return errors.New("The X509 credential value must be of type *Signer for X509 credential")
	}
	cred.val = s
	return nil
}

// Load loads the certificate and key from the location specified by
// certFile attribute using the BCCSP of the client.
func (cred *Credential) Load() error {
	cert, err := ioutil.ReadFile(cred.certFile)
	if err != nil {
		log.Debugf("No certificate found at %s", cred.certFile)
		return err
	}
	csp := cred.getCSP()
	key, _, _, err := util.GetSignerFromCertFile(cred.certFile, csp)
	if err != nil {
		log.Debug("No key found in the CCCSP keystore, attempting fallback")
		key, err = util.ImportCCCSPKeyFromPEM(cred.keyFile, csp, true)
		if err != nil {
			return errors.WithMessage(err, fmt.Sprintf("Could not find the private key in the CCCSP keystore nor in the keyfile %s", cred.keyFile))
		}
	}
	cred.val, err = NewSigner(key, cert)
	if err != nil {
		return err
	}
	return nil
}

// Store stores the certificate associated with this X509 credential to the location
// specified  by certFile attribute
func (cred *Credential) Store() error {
	if cred.val == nil {
		return errors.New("X509 Credential value is not set")
	}
	err := util.WriteFile(cred.certFile, cred.val.Cert(), 0644)
	if err != nil {
		return errors.WithMessage(err, "Failed to store the certificate")
	}
	log.Infof("Stored client certificate at %s", cred.certFile)
	return nil
}

// RevokeSelf revokes this X509 credential
func (cred *Credential) RevokeSelf() (*credential.RevocationResponse, error) {
	name, err := cred.EnrollmentID()
	if err != nil {
		return nil, err
	}
	val := cred.val
	serial := util.GetSerialAsHex(val.cert.SerialNumber)
	aki := hex.EncodeToString(val.cert.AuthorityKeyId)
	req := &credential.RevocationRequest{
		Serial: serial,
		AKI:    aki,
	}

	id := cred.client.NewX509Identity(name, []credential.Credential{cred})
	return id.Revoke(req)
}

// CreateToken creates token based on this X509 credential
func (cred *Credential) CreateToken(req *http.Request, reqBody []byte) (string, error) {
	return util.CreateToken(cred.getCSP(), cred.val.certBytes, cred.val.key, req.Method, req.URL.RequestURI(), reqBody)
}

func (cred *Credential) getCSP() cccsp.CCCSP {
	if cred.client != nil && cred.client.GetCSP() != nil {
		return cred.client.GetCSP()
	}

	panic("CCCSP is nil, this is a development issue")
}
