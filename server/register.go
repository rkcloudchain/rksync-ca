package server

import (
	"fmt"
	"net/http"

	"github.com/cloudflare/cfssl/log"
	"github.com/pkg/errors"
	"github.com/rkcloudchain/courier-ca/api"
	"github.com/rkcloudchain/courier-ca/api/registry"
	"github.com/rkcloudchain/courier-ca/attrmgr"
	"github.com/rkcloudchain/courier-ca/util"
)

// Handle a register request
func registerHandler(s *Server, resp http.ResponseWriter, req *http.Request) (interface{}, error) {
	ca := s.GetCA()
	return register(ca, resp, req)
}

func register(ca *CA, w http.ResponseWriter, r *http.Request) (interface{}, error) {
	var req api.RegistrationRequestNet
	err := ReadBody(r, &req)
	if err != nil {
		return nil, err
	}

	secret, err := registerUser(&req, ca)
	if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("Registration of '%s' failed", req.Name))
	}

	resp := &api.RegistrationResponseNet{
		RegistrationResponse: api.RegistrationResponse{Secret: secret},
	}
	return resp, nil
}

// Registers a new identity
func registerUser(req *api.RegistrationRequestNet, ca *CA) (string, error) {
	log.Debugf("Registering user id: %s", req.Name)
	var err error

	if req.Secret == "" {
		req.Secret = util.RandomString(12)
	}

	req.MaxEnrollments, err = getMaxEnrollments(req.MaxEnrollments, ca.Config.Registry.MaxEnrollments)
	if err != nil {
		return "", err
	}

	addAttributeToRequest(attrmgr.EnrollmentID, req.Name, &req.Attributes)

	insert := registry.UserInfo{
		Name:           req.Name,
		Pass:           req.Secret,
		Attributes:     req.Attributes,
		MaxEnrollments: req.MaxEnrollments,
	}

	registry := ca.registry

	_, err = registry.GetUser(req.Name, nil)
	if err == nil {
		return "", errors.Errorf("Identity '%s' is already registered", req.Name)
	}

	err = registry.InsertUser(&insert)
	if err != nil {
		return "", err
	}

	return req.Secret, nil
}

// Add an attribute to the registration request if not already found.
func addAttributeToRequest(name, value string, attributes *[]api.Attribute) {
	*attributes = append(*attributes, api.Attribute{Name: name, Value: value, ECert: true})
}
