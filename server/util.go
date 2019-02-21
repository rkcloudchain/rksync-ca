package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/pkg/errors"
	"github.com/rkcloudchain/rksync-ca/api"
	"github.com/rkcloudchain/rksync-ca/attrmgr"
	caerrors "github.com/rkcloudchain/rksync-ca/errors"
)

var clientAuthTypes = map[string]tls.ClientAuthType{
	"noclientcert":               tls.NoClientCert,
	"requestclientcert":          tls.RequestClientCert,
	"requireanyclientcert":       tls.RequireAnyClientCert,
	"verifyclientcertifgiven":    tls.VerifyClientCertIfGiven,
	"requireandverifyclientcert": tls.RequireAndVerifyClientCert,
}

// LoadPEMCertPool loads a pool of PEM certificate from list of files
func LoadPEMCertPool(certFiles []string) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()

	if len(certFiles) > 0 {
		for _, cert := range certFiles {
			log.Debugf("Reading cert file: %s", cert)
			pemCerts, err := ioutil.ReadFile(cert)
			if err != nil {
				return nil, err
			}

			log.Debugf("Appending cert %s to pool", cert)
			if !certPool.AppendCertsFromPEM(pemCerts) {
				return nil, errors.New("Failed to load cert pool")
			}
		}
	}

	return certPool, nil
}

// ReadBody reads the request body and JSON unmarshals into 'body'
func ReadBody(r *http.Request, body interface{}) error {
	empty, err := TryReadBody(r, body)
	if err != nil {
		return err
	}
	if empty {
		return caerrors.NewHTTPErr(400, caerrors.ErrEmptyReqBody, "Empty request body")
	}
	return nil
}

// TryReadBody reads the request body into 'body' if not empty
func TryReadBody(r *http.Request, body interface{}) (bool, error) {
	buf, err := ReadBodyBytes(r)
	if err != nil {
		return false, err
	}
	empty := len(buf) == 0
	if !empty {
		err = json.Unmarshal(buf, body)
		if err != nil {
			return true, caerrors.NewHTTPErr(400, caerrors.ErrBadReqBody, "Invalid request body: %s; body=%s", err, string(buf))
		}
	}
	return empty, nil
}

// ReadBodyBytes reads the request body and returns bytes
func ReadBodyBytes(r *http.Request) ([]byte, error) {
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, caerrors.NewHTTPErr(400, caerrors.ErrReadingReqBody, "Failed reading request body: %s", err)
	}
	return buf, nil
}

// GetAttrExtension returns an attribute extension to place into a signing request
func GetAttrExtension(ca *CA, attrReqs []*api.AttributeRequest, id, profile string) (*signer.Extension, error) {
	ui, err := ca.registry.GetUser(id, nil)
	if err != nil {
		return nil, err
	}

	allAttrs, err := ui.GetAttributes(nil)
	if err != nil {
		return nil, err
	}
	if attrReqs == nil {
		attrReqs = getDefaultAttrReqs(allAttrs)
		if attrReqs == nil {
			return nil, nil
		}
	}
	attrs, err := ca.attrMgr.ProcessAttributeRequests(
		convertAttrReqs(attrReqs),
		convertAttrs(allAttrs),
	)
	if err != nil {
		return nil, err
	}
	if attrs != nil {
		buf, err := json.Marshal(attrs)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to marshal attributes")
		}
		ext := &signer.Extension{
			ID:       config.OID(attrmgr.AttrOID),
			Critical: false,
			Value:    hex.EncodeToString(buf),
		}
		log.Debugf("Attribute extension being added to certificate is: %+v", ext)
		return ext, nil
	}
	return nil, nil
}

// Returns attribute requests for attributes which should by default be added to an ECert
func getDefaultAttrReqs(attrs []api.Attribute) []*api.AttributeRequest {
	count := 0
	for _, attr := range attrs {
		if attr.ECert {
			count++
		}
	}
	if count == 0 {
		return nil
	}
	reqs := make([]*api.AttributeRequest, count)
	count = 0
	for _, attr := range attrs {
		if attr.ECert {
			reqs[count] = &api.AttributeRequest{Name: attr.Name}
			count++
		}
	}
	return reqs
}

func convertAttrReqs(attrReqs []*api.AttributeRequest) []attrmgr.AttributeRequest {
	rtn := make([]attrmgr.AttributeRequest, len(attrReqs))
	for i := range attrReqs {
		rtn[i] = attrmgr.AttributeRequest(attrReqs[i])
	}
	return rtn
}

func convertAttrs(attrs []api.Attribute) []attrmgr.Attribute {
	rtn := make([]attrmgr.Attribute, len(attrs))
	for i := range attrs {
		rtn[i] = attrmgr.Attribute(&attrs[i])
	}
	return rtn
}

func getMaxEnrollments(userMaxEnrollments int, caMaxEnrollments int) (int, error) {
	log.Debugf("Max enrollment value verification - User specified max enrollment: %d, CA max enrollment: %d", userMaxEnrollments, caMaxEnrollments)

	if userMaxEnrollments < -1 {
		return 0, errors.Errorf("Max enrollment in registration request may not be less than -1, but was %d", userMaxEnrollments)
	}

	switch caMaxEnrollments {
	case -1:
		if userMaxEnrollments == 0 {
			return caMaxEnrollments, nil
		}
		return userMaxEnrollments, nil
	case 0:
		return 0, errors.New("Registration is disabled")
	default:
		switch userMaxEnrollments {
		case -1:
			return 0, errors.New("Registration for infinite enrollments is not allowed")
		case 0:
			return caMaxEnrollments, nil
		default:
			if userMaxEnrollments > caMaxEnrollments {
				return 0, errors.Errorf("Requested enrollments (%d) exceeds maximum allowable enrollments (%d)",
					userMaxEnrollments, caMaxEnrollments)
			}
			return userMaxEnrollments, nil
		}
	}
}
