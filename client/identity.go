package client

import (
	"github.com/pkg/errors"
	"github.com/rkcloudchain/rksync-ca/api/credential"
)

// Identity is rksync-ca's implementation of an identity
type identity struct {
	name   string
	client *Client
	cred   *credential.Credential
}

// NewIdentity is the constructor for identity
func NewIdentity(client *Client, name string, cred *credential.Credential) credential.Identity {
	id := new(identity)
	id.name = name
	id.client = client
	id.cred = cred
	return id
}

// GetECert returns the enrollment certificate signer for this identity
func (i *identity) GetECert() *credential.Signer {
	v, _ := i.cred.Val()
	if v != nil {
		s, _ := v.(*credential.Signer)
		return s
	}
	return nil
}

// GetName returns the identity name
func (i *identity) GetName() string {
	return i.name
}

// GetX509Credential returns X509 credential of this identity
func (i *identity) GetX509Credential() *credential.Credential {
	return i.cred
}

// Store writes my identity info to dist
func (i *identity) Store() error {
	if i.client == nil {
		return errors.New("An identity with no client my not be stored")
	}
	return i.cred.Store()
}
