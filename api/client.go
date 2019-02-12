package api

import "github.com/cloudflare/cfssl/csr"

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
