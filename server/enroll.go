package server

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	cfcfg "github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/pkg/errors"
	"github.com/rkcloudchain/rksync-ca/api"
	caerrors "github.com/rkcloudchain/rksync-ca/errors"
)

const (
	commonNameLength             = 64
	serialNumberLength           = 64
	countryNameLength            = 2
	localityNameLength           = 128
	stateOrProvinceNameLength    = 128
	organizationNameLength       = 64
	organizationalUnitNameLength = 64
)

var (
	// The X.509 BasicConstraints object identifier (RFC 5280, 4.2.1.9)
	basicConstraintsOID   = asn1.ObjectIdentifier{2, 5, 29, 19}
	commonNameOID         = asn1.ObjectIdentifier{2, 5, 4, 3}
	serialNumberOID       = asn1.ObjectIdentifier{2, 5, 4, 5}
	countryOID            = asn1.ObjectIdentifier{2, 5, 4, 6}
	localityOID           = asn1.ObjectIdentifier{2, 5, 4, 7}
	stateOID              = asn1.ObjectIdentifier{2, 5, 4, 8}
	organizationOID       = asn1.ObjectIdentifier{2, 5, 4, 10}
	organizationalUnitOID = asn1.ObjectIdentifier{2, 5, 4, 11}
)

// Handle an enroll request
func enrollHandler(s *Server, resp http.ResponseWriter, req *http.Request) (interface{}, error) {
	username, password, ok := req.BasicAuth()
	if !ok {
		return nil, caerrors.NewAuthenticationErr(caerrors.ErrNoUserPass, "No user/pass in authorization header")
	}

	ca := s.GetCA()
	log.Debugf("ca.Config: %+v", ca.Config)
	caMaxEnrollments := ca.Config.Registry.MaxEnrollments
	if caMaxEnrollments == 0 {
		return nil, caerrors.NewAuthenticationErr(caerrors.ErrEnrollDisabled, "Enroll is disabled")
	}

	ui, err := ca.registry.GetUser(username, nil)
	if err != nil {
		return nil, caerrors.NewAuthenticationErr(caerrors.ErrInvalidUser, "Failed to get user: %s", username)
	}

	attempts := ui.GetFailedLoginAttempts()
	if attempts >= 10 {
		msg := fmt.Sprintf("Incorrect password entered %d times, max incorrect password limit of 10 reached", attempts)
		log.Error(msg)
		return nil, caerrors.NewHTTPErr(401, caerrors.ErrPasswordAttempts, msg)
	}

	err = ui.Login(password, caMaxEnrollments)
	if err != nil {
		return nil, caerrors.NewAuthenticationErr(caerrors.ErrInvalidPass, "Login failure: %s", err)
	}

	res, err := handleEnroll(ca, req, username)
	if err != nil {
		return nil, err
	}

	err = ui.LoginComplete()
	if err != nil {
		return nil, err
	}

	return res, nil
}

func handleEnroll(ca *CA, r *http.Request, id string) (interface{}, error) {
	var req api.EnrollmentRequestNet
	err := ReadBody(r, &req)
	if err != nil {
		return nil, err
	}

	if req.NotAfter.IsZero() {
		profile := ca.Config.Signing.Default
		if req.Profile != "" && ca.Config.Signing != nil &&
			ca.Config.Signing.Profiles != nil && ca.Config.Signing.Profiles[req.Profile] != nil {
			profile = ca.Config.Signing.Profiles[req.Profile]
		}
		req.NotAfter = time.Now().Round(time.Minute).Add(profile.Expiry).UTC()
	}
	caexpiry, err := ca.getCACertExpiry()
	if err != nil {
		log.Errorf("Failed to get CA certificate information: %s", err)
		return nil, errors.New("Failed to get CA certificate information")
	}

	if !caexpiry.IsZero() && req.NotAfter.After(caexpiry) {
		log.Debugf("Request expiry '%s' is after the CA certificate expiry '%s'. Will use CA cert expiry", req.NotAfter, caexpiry)
		req.NotAfter = caexpiry
	}

	err = processSignRequest(id, &req.SignRequest, ca)
	if err != nil {
		return nil, err
	}

	ext, err := GetAttrExtension(ca, req.AttrReqs, id, req.Profile)
	if err != nil {
		return nil, err
	}
	if ext != nil {
		log.Debugf("Adding attribute extension to CSR: %+v", ext)
		req.Extensions = append(req.Extensions, *ext)
	}

	cert, err := ca.enrollSigner.Sign(req.SignRequest)
	if err != nil {
		return nil, errors.WithMessage(err, "Certificate signing failure")
	}

	resp := &api.EnrollmentResponseNet{
		Cert: base64.StdEncoding.EncodeToString(cert),
	}
	err = ca.fillCAInfo(&resp.ServerInfo)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// Process the sign request.
func processSignRequest(id string, req *signer.SignRequest, ca *CA) error {
	block, _ := pem.Decode([]byte(req.Request))
	if block == nil {
		return cferr.New(cferr.CSRError, cferr.DecodeFailed)
	}
	if block.Type != "NEW CERTIFICATE REQUEST" && block.Type != "CERTIFICATE REQUEST" {
		return cferr.Wrap(cferr.CSRError, cferr.BadRequest, errors.New("not a certificate or csr"))
	}
	csrReq, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return err
	}
	log.Debugf("Processing sign request: id=%s, CommonName=%s, Subject=%+v", id, csrReq.Subject.CommonName, csrReq.Subject)
	if (req.Subject != nil && req.Subject.CN != id) || csrReq.Subject.CommonName != id {
		return errors.New("The CSR subject common name must equal the enrollment ID")
	}

	isForCACert, err := isRequestForCASigningCert(csrReq, ca, req.Profile)
	if err != nil {
		return err
	}
	if isForCACert {
		err := ca.attributeIsTrue(id, "cr.IntermediateCA")
		if err != nil {
			return err
		}
	}

	err = csrInputLengthCheck(csrReq)
	if err != nil {
		return err
	}

	log.Debug("Finished processing sign request")
	return nil
}

// Check to see if this is a request for a CA signing certificate.
func isRequestForCASigningCert(csrReq *x509.CertificateRequest, ca *CA, profile string) (bool, error) {
	sp := getSigningProfile(ca, profile)
	if sp == nil {
		return false, errors.Errorf("Invalid profile: '%s'", profile)
	}
	if sp.CAConstraint.IsCA {
		log.Debugf("Request is for a CA signing certificate as set in profile '%s'", profile)
		return true, nil
	}

	for _, val := range csrReq.Extensions {
		if val.Id.Equal(basicConstraintsOID) {
			var constraints csr.BasicConstraints
			var rest []byte
			var err error

			if rest, err = asn1.Unmarshal(val.Value, &constraints); err != nil {
				return false, caerrors.NewHTTPErr(400, caerrors.ErrBadCSR, "Failed parsing CSR constraints: %s", err)
			} else if len(rest) != 0 {
				return false, caerrors.NewHTTPErr(400, caerrors.ErrBadCSR, "Trailing data after X.509 BasicConstraints")
			}
			if constraints.IsCA {
				log.Debug("Request is for a CA signing certificate as indicated in the CSR")
				return true, nil
			}
		}
	}

	log.Debug("Request is not for CA signing certificate")
	return false, nil
}

func getSigningProfile(ca *CA, profile string) *cfcfg.SigningProfile {
	if profile == "" {
		return ca.Config.Signing.Default
	}
	return ca.Config.Signing.Profiles[profile]
}

// Checks to make sure that character limits are not exceeded for CSR fields
func csrInputLengthCheck(req *x509.CertificateRequest) error {
	log.Debug("Checking CSR fields to make sure that they do not exceed maximum character limits")

	for _, n := range req.Subject.Names {
		value := n.Value.(string)
		switch {
		case n.Type.Equal(commonNameOID):
			if len(value) > commonNameLength {
				return errors.Errorf("The CN '%s' exceeds the maximum character limit of %d", value, commonNameLength)
			}
		case n.Type.Equal(serialNumberOID):
			if len(value) > serialNumberLength {
				return errors.Errorf("The serial number '%s' exceeds the maximum character limit of %d", value, serialNumberLength)
			}
		case n.Type.Equal(organizationalUnitOID):
			if len(value) > organizationalUnitNameLength {
				return errors.Errorf("The organizational unit name '%s' exceeds the maximum character limit of %d", value, organizationalUnitNameLength)
			}
		case n.Type.Equal(organizationOID):
			if len(value) > organizationNameLength {
				return errors.Errorf("The organization name '%s' exceeds the maximum character limit of %d", value, organizationNameLength)
			}
		case n.Type.Equal(countryOID):
			if len(value) > countryNameLength {
				return errors.Errorf("The country name '%s' exceeds the maximum character limit of %d", value, countryNameLength)
			}
		case n.Type.Equal(localityOID):
			if len(value) > localityNameLength {
				return errors.Errorf("The locality name '%s' exceeds the maximum character limit of %d", value, localityNameLength)
			}
		case n.Type.Equal(stateOID):
			if len(value) > stateOrProvinceNameLength {
				return errors.Errorf("The state name '%s' exceeds the maximum character limit of %d", value, stateOrProvinceNameLength)
			}
		}
	}

	return nil
}
