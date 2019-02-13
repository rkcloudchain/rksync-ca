package credential

import "net/http"

// Credential represents on credential of an identity
type Credential interface {
	// Type returns type of this credential
	Type() string
	// EnrollmentID returns enrollment ID associated with this credential
	EnrollmentID() (string, error)
	// Stores the credential value to disk
	Store() error
	// Loads the credential value from disk and sets the value of this credential
	Load() error
	// Val returns credential value
	Val() (interface{}, error)
	// Sets the credential value
	SetVal(val interface{}) error
	// Submits revoke request to the Courier CA server to revoke this credential
	RevokeSelf() (*RevocationResponse, error)
	// CreateToken returns authorization token for the specified request with
	// specified body
	CreateToken(req *http.Request, reqBody []byte) (string, error)
}

// RevocationRequest is a revocation request for a single certificate or all certificates
// associated with an identity
type RevocationRequest struct {
	Name   string `json:"id,omitempty"`
	Serial string `json:"serial,omitempty"`
	AKI    string `json:"aki,omitempty"`
	Reason string `json:"reason,omitempty"`
	CAName string `json:"caname,omitempty"`
	GenCRL bool   `json:"gencrl,omitempty"`
}

// RevocationResponse represents response from the server for a revocation request
type RevocationResponse struct {
	RevokedCerts []RevokedCert
	// CRL is PEM-encoded certificate revocation list (CRL) that contains all unexpired revoked certificates
	CRL []byte
}

// RevokedCert represents a revoked certificate
type RevokedCert struct {
	// Serial number of the revoked certificate
	Serial string
	// AKI of the revoked certificate
	AKI string
}
