package x509

import (
	"crypto/x509"
	"fmt"

	"github.com/pkg/errors"
	"github.com/rkcloudchain/cccsp"
	"github.com/rkcloudchain/rksync-ca/attrmgr"
	"github.com/rkcloudchain/rksync-ca/util"
)

// NewSigner is constructor for Signer
func NewSigner(key cccsp.Key, cert []byte) (*Signer, error) {
	s := &Signer{
		key:       key,
		certBytes: cert,
	}
	var err error
	s.cert, err = util.GetX509CertificateFromPEM(s.certBytes)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to unmarshal X509 certificate bytes")
	}
	s.name = util.GetEnrollmentIDFromX509Certificate(s.cert)
	return s, nil
}

// Signer represents a signer
type Signer struct {
	key       cccsp.Key
	certBytes []byte
	cert      *x509.Certificate
	name      string
}

// Key returns the key bytes of this signer
func (s *Signer) Key() cccsp.Key {
	return s.key
}

// Cert returns the cert bytes of this signer
func (s *Signer) Cert() []byte {
	return s.certBytes
}

// GetX509Cert returns the x509 certificate for this signer
func (s *Signer) GetX509Cert() *x509.Certificate {
	return s.cert
}

// GetName returns common name that is retrieved from the Subject of the certificate
func (s *Signer) GetName() string {
	return s.name
}

// Attributes returns the attributes that are in the certificate
func (s *Signer) Attributes() (*attrmgr.Attributes, error) {
	cert := s.GetX509Cert()
	attrs, err := attrmgr.New().GetAttributesFromCert(cert)
	if err != nil {
		return nil, fmt.Errorf("Failed getting attributes for '%s': %s", s.name, err)
	}
	return attrs, nil
}
