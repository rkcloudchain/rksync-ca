package api

import "github.com/cloudflare/cfssl/signer"

// EnrollmentRequestNet is a request to enroll an identity
type EnrollmentRequestNet struct {
	signer.SignRequest
	CAName   string
	AttrReqs []*AttributeRequest `json:"attr_reqs,omitempty"`
}

// CAInfoResponseNet is the response to the GET /info request
type CAInfoResponseNet struct {
	CAName  string
	CAChain string
	Version string
}

// EnrollmentResponseNet is the response to the /enroll request
type EnrollmentResponseNet struct {
	Cert       string
	ServerInfo CAInfoResponseNet
}
