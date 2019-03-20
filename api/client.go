package api

import (
	"github.com/cloudflare/cfssl/csr"
	"github.com/rkcloudchain/rksync-ca/api/credential/x509"
)

// CSRInfo is Certificate Signing Request (CSR) Information
type CSRInfo struct {
	CN           string           `json:"CN"`
	Names        []csr.Name       `json:"names,omitempty"`
	Hosts        []string         `json:"hosts,omitempty"`
	KeyRequest   *BasicKeyRequest `json:"key,omitempty"`
	CA           *csr.CAConfig    `json:"ca,omitempty" hide:"true"`
	SerialNumber string           `json:"serial_number,omitempty"`
}

// BasicKeyRequest encapsulates size and algorithm for the key to be generated
type BasicKeyRequest struct {
	Algo string `json:"algo" yaml:"algo" help:"Specify key algorithm"`
	Size int    `json:"size" yaml:"size" help:"Specify key size"`
}

// Attribute is a name and value pair
type Attribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	ECert bool   `json:"ecert,omitempty"`
}

// GetName returns the name of the attribute
func (a *Attribute) GetName() string {
	return a.Name
}

// GetValue returns the value of the attribute
func (a *Attribute) GetValue() string {
	return a.Value
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

// GetCAInfoResponse is the response from the GetCAInfo call
type GetCAInfoResponse struct {
	// CAName is the name of the CA
	CAName string
	// CAChain is the PEM-encoded bytes of the rksync-ca server's CA chain.
	CAChain []byte
	// Version of the server
	Version string
}

// EnrollmentResponse is the response from Client.Enroll and Identity.Reenroll
type EnrollmentResponse struct {
	Identity x509.Identity
	CAInfo   GetCAInfoResponse
}

// RegistrationRequest for a new identity
type RegistrationRequest struct {
	Name           string      `json:"id"`
	Secret         string      `json:"secret,omitempty"`
	MaxEnrollments int         `json:"max_enrollments,omitempty"`
	Attributes     []Attribute `json:"attrs,omitempty"`
	CAName         string      `json:"caname,omitempty"`
}

// RegistrationResponse is a registration response
type RegistrationResponse struct {
	Secret string `json:"secret"`
}
