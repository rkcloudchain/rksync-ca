package api

import (
	"github.com/cloudflare/cfssl/csr"
	"github.com/rkcloudchain/courier-ca/api/credential"
)

// CSRInfo is Certificate Signing Request (CSR) Information
type CSRInfo struct {
	CN           string           `json:"CN"`
	Names        []csr.Name       `json:"names,omitempty"`
	Hosts        []string         `json:"hosts,omitempty"`
	KeyRequest   *BasicKeyRequest `json:"key,omitempty"`
	CA           *csr.CAConfig    `json:"ca,omitempty"`
	SerialNumber string           `json:"serial_number,omitempty"`
}

// BasicKeyRequest encapsulates size and algorithm for the key to be generated
type BasicKeyRequest struct {
	Algo string `json:"algo" yaml:"algo"`
	Size int    `json:"size" yaml:"size"`
}

// EnrollmentRequest is a request to enroll an identity
type EnrollmentRequest struct {
	Name     string              `json:"name"`
	Secret   string              `json:"secret,omitempty"`
	CAName   string              `json:"caname,omitempty"`
	AttrReqs []*AttributeRequest `json:"attr_reqs,omitempty"`
	Profile  string              `json:"profile,omitempty"`
	CSR      *CSRInfo            `json:"csr,omitempty"`
}

// AttributeRequest is a request for an attribute.
type AttributeRequest struct {
	Name     string `json:"name"`
	Optional bool   `json:"optional,omitempty"`
}

// GetName returns the name of an attribute being requested
func (ar *AttributeRequest) GetName() string {
	return ar.Name
}

// IsRequired returns true if the attribute being requested is required
func (ar *AttributeRequest) IsRequired() bool {
	return !ar.Optional
}

// NewBasicKeyRequest returns the BasicKeyRequest object that is constructed
// from the object returned by the csr.NewBasicKeyRequest() function
func NewBasicKeyRequest() *BasicKeyRequest {
	bkr := csr.NewBasicKeyRequest()
	return &BasicKeyRequest{Algo: bkr.A, Size: bkr.S}
}

// Identity is courier-ca's implementation of an identity
type Identity struct {
	Name  string
	Creds []credential.Credential
}

// GetCAInfoResponse is the response from the GetCAInfo call
type GetCAInfoResponse struct {
	// CAName is the name of the CA
	CAName string
	// CAChain is the PEM-encoded bytes of the courier-ca server's CA chain.
	CAChain []byte
	// Version of the server
	Version string
}

// EnrollmentResponse is the response from Client.Enroll and Identity.Reenroll
type EnrollmentResponse struct {
	Identity *Identity
	CAInfo   GetCAInfoResponse
}
