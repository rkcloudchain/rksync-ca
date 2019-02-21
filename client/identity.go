package client

import (
	"encoding/base64"
	"net/http"

	"github.com/cloudflare/cfssl/log"
	"github.com/pkg/errors"
	"github.com/rkcloudchain/rksync-ca/api/credential"
	x509cred "github.com/rkcloudchain/rksync-ca/api/credential/x509"
	"github.com/rkcloudchain/rksync-ca/util"
)

// Identity is rksync-ca's implementation of an identity
type Identity struct {
	name   string
	client *Client
	creds  []credential.Credential
}

// NewIdentity is the constructor for identity
func NewIdentity(client *Client, name string, creds []credential.Credential) *Identity {
	id := new(Identity)
	id.name = name
	id.client = client
	id.creds = creds
	return id
}

// GetName returns the identity name
func (i *Identity) GetName() string {
	return i.name
}

// GetX509Credential returns X509 credential of this identity
func (i *Identity) GetX509Credential() credential.Credential {
	for _, cred := range i.creds {
		if cred.Type() == x509cred.CredType {
			return cred
		}
	}
	return nil
}

// Revoke the identity associated with 'id'
func (i *Identity) Revoke(req *credential.RevocationRequest) (*credential.RevocationResponse, error) {
	log.Debugf("Entering identity.Revoke %+v", req)
	reqBody, err := util.Marshal(req, "RevocationRequest")
	if err != nil {
		return nil, err
	}
	var result revocationResponseNet
	err = i.Post("revoke", reqBody, &result, nil)
	if err != nil {
		return nil, err
	}
	log.Debugf("Successfully revoked certificates: %+v", req)
	crl, err := base64.StdEncoding.DecodeString(result.CRL)
	if err != nil {
		return nil, err
	}
	return &credential.RevocationResponse{RevokedCerts: result.RevokedCerts, CRL: crl}, nil
}

// Post sends arbitrary request body to an endpoint.
func (i *Identity) Post(endpoint string, reqBody []byte, result interface{}, queryParam map[string]string) error {
	req, err := i.client.newPost(endpoint, reqBody)
	if err != nil {
		return err
	}
	if queryParam != nil {
		for key, value := range queryParam {
			addQueryParam(req, key, value)
		}
	}
	err = i.addTokenAuthHdr(req, reqBody)
	if err != nil {
		return err
	}
	return i.client.SendReq(req, result)
}

func (i *Identity) addTokenAuthHdr(req *http.Request, body []byte) error {
	log.Debug("Adding token-based authorization header")
	var token string
	var err error
	for _, cred := range i.creds {
		token, err = cred.CreateToken(req, body)
		if err != nil {
			return errors.WithMessage(err, "Failed to add token authorization header")
		}
		break
	}
	req.Header.Set("Authorization", token)
	return nil
}

func addQueryParam(req *http.Request, name, value string) {
	url := req.URL.Query()
	url.Add(name, value)
	req.URL.RawQuery = url.Encode()
}

type revocationResponseNet struct {
	RevokedCerts []credential.RevokedCert
	CRL          string
}
