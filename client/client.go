package client

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	cfsslapi "github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"
	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
	"github.com/rkcloudchain/cccsp"
	"github.com/rkcloudchain/rksync-ca/api"
	"github.com/rkcloudchain/rksync-ca/api/credential"
	"github.com/rkcloudchain/rksync-ca/config"
	"github.com/rkcloudchain/rksync-ca/util"
)

// Client is the rksync-ca client object
type Client struct {
	// The client's home directory
	HomeDir string
	// The client's configuration
	Config *config.ClientConfig
	// HTTP client associated with this rksync CA client
	httpClient *http.Client

	csp               cccsp.CCCSP
	initialized       bool
	keyFile, certFile string
	caCertsDir        string
}

// Init initialize the client
func (c *Client) Init() error {
	if !c.initialized {
		cfg := c.Config
		log.Debugf("Initializing client with config %+v", cfg)

		if cfg.CSPDir == "" {
			cfg.CSPDir = "csp"
		}
		cspDir, err := util.MakeFileAbs(cfg.CSPDir, c.HomeDir)
		if err != nil {
			return err
		}
		cfg.CSPDir = cspDir

		keyDir := filepath.Join(cspDir, "keystore")
		err = os.MkdirAll(keyDir, 0700)
		if err != nil {
			return errors.Wrap(err, "Failed to create keystore directory")
		}
		c.keyFile = filepath.Join(keyDir, "key.pem")

		certDir := filepath.Join(cspDir, "signcerts")
		err = os.MkdirAll(certDir, 0755)
		if err != nil {
			return errors.Wrap(err, "Failed to create signcerts directory")
		}
		c.certFile = filepath.Join(certDir, "cert.pem")

		c.caCertsDir = filepath.Join(cspDir, "cacerts")
		err = os.MkdirAll(c.caCertsDir, 0755)
		if err != nil {
			return errors.Wrap(err, "Failed to create cacerts directory")
		}

		c.csp, err = util.InitCCCSP(keyDir)
		if err != nil {
			return err
		}

		err = c.initHTTPClient()
		if err != nil {
			return err
		}

		c.initialized = true
	}
	return nil
}

func (c *Client) initHTTPClient() error {
	tr := new(http.Transport)
	if c.Config.TLS.Enabled {
		log.Info("TLS enabled")

		err := config.AbsTLSClient(&c.Config.TLS, c.HomeDir)
		if err != nil {
			return err
		}

		tlsConfig, err2 := config.GetClientTLSConfig(&c.Config.TLS, c.csp)
		if err2 != nil {
			return errors.Errorf("Failed to get client TLS config: %s", err2)
		}
		tlsConfig.CipherSuites = config.DefaultCipherSuites
		tr.TLSClientConfig = tlsConfig
	}
	c.httpClient = &http.Client{Transport: tr}
	return nil
}

// Register registers a new identity
func (c *Client) Register(req *api.RegistrationRequest) (rr *api.RegistrationResponse, err error) {
	log.Debugf("Register %+v", req)

	if req.Name == "" {
		return nil, errors.New("Register was called without a Name set")
	}

	reqBody, err := util.Marshal(req, "RegistrationRequest")
	if err != nil {
		return nil, err
	}

	post, err := c.newPost("register", reqBody)
	if err != nil {
		return nil, err
	}

	var resp api.RegistrationResponse
	err = c.SendReq(post, &resp)
	if err != nil {
		return nil, err
	}

	log.Debug("The register request completed successfully")
	return &resp, nil
}

// Enroll enrolls a new identity
func (c *Client) Enroll(req *api.EnrollmentRequest) (*api.EnrollmentResponse, error) {
	log.Debugf("Enrolling %+v", req)

	err := c.Init()
	if err != nil {
		return nil, err
	}

	return c.handleX509Enroll(req)
}

// GenCSR generates a CSR (Certificate Signing Request)
func (c *Client) GenCSR(req *api.CSRInfo, id string) ([]byte, cccsp.Key, error) {
	log.Debugf("GenCSR %+v", req)

	err := c.Init()
	if err != nil {
		return nil, nil, err
	}

	cr := c.newCertificateRequest(req)
	cr.CN = id

	if cr.KeyRequest == nil || (cr.KeyRequest.Size() == 0 && cr.KeyRequest.Algo() == "") {
		cr.KeyRequest = newCfsslBasicKeyRequest(api.NewBasicKeyRequest())
	}

	key, cspSigner, err := util.CCCSPKeyRequestGenerate(cr, c.csp)
	if err != nil {
		log.Debugf("failed generating BCCSP key: %s", err)
		return nil, nil, err
	}

	csrPEM, err := csr.Generate(cspSigner, cr)
	if err != nil {
		log.Debugf("failed generating CSR: %s", err)
		return nil, nil, err
	}

	return csrPEM, key, nil
}

func (c *Client) handleX509Enroll(req *api.EnrollmentRequest) (*api.EnrollmentResponse, error) {
	csrPEM, key, err := c.GenCSR(req.CSR, req.Name)
	if err != nil {
		return nil, errors.WithMessage(err, "Failure generating CSR")
	}

	reqNet := &api.EnrollmentRequestNet{
		CAName:   req.CAName,
		AttrReqs: req.AttrReqs,
	}

	if req.CSR != nil {
		reqNet.SignRequest.Hosts = req.CSR.Hosts
	}
	reqNet.SignRequest.Request = string(csrPEM)
	reqNet.SignRequest.Profile = req.Profile

	body, err := util.Marshal(reqNet, "SignRequest")
	if err != nil {
		return nil, err
	}

	post, err := c.newPost("enroll", body)
	if err != nil {
		return nil, err
	}
	post.SetBasicAuth(req.Name, req.Secret)
	var result api.EnrollmentResponseNet
	err = c.SendReq(post, &result)
	if err != nil {
		return nil, err
	}

	resp, err := c.newEnrollmentResponse(&result, req.Name, key)
	if err != nil {
		return nil, err
	}

	err = resp.Identity.Store()
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to store enrollment information")
	}

	err = storeCAChain(c.Config, req.Profile, &resp.CAInfo)
	return resp, err
}

// newEnrollmentResponse creates a client enrollment response from a network response
func (c *Client) newEnrollmentResponse(result *api.EnrollmentResponseNet, id string, key cccsp.Key) (*api.EnrollmentResponse, error) {
	log.Debugf("newEnrollmentResponse %s", id)
	certBytes, err := base64.StdEncoding.DecodeString(result.Cert)
	if err != nil {
		return nil, errors.WithMessage(err, "Invalid response format from server")
	}
	signer, err := credential.NewSigner(key, certBytes)
	if err != nil {
		return nil, err
	}
	x509Cred := credential.NewCredential(c.certFile, c.keyFile, c)
	err = x509Cred.SetVal(signer)
	if err != nil {
		return nil, err
	}
	identity := NewIdentity(c, id, x509Cred)

	resp := &api.EnrollmentResponse{
		Identity: NewIdentity(c, identity.GetName(), identity.GetX509Credential()),
	}
	err = c.net2LocalCAInfo(&result.ServerInfo, &resp.CAInfo)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Convert from network to local CA information
func (c *Client) net2LocalCAInfo(net *api.CAInfoResponseNet, local *api.GetCAInfoResponse) error {
	caChain, err := base64.StdEncoding.DecodeString(net.CAChain)
	if err != nil {
		return errors.WithMessage(err, "Failed to decode CA chain")
	}
	local.CAName = net.CAName
	local.CAChain = caChain
	local.Version = net.Version
	return nil
}

// NewX509Identity creates a new identity
func (c *Client) NewX509Identity(name string, cred *credential.Credential) credential.Identity {
	return NewIdentity(c, name, cred)
}

// GetCSP returns BCCSP instance associated with this client
func (c *Client) GetCSP() cccsp.CCCSP {
	return c.csp
}

// SendReq sends a request to the rksync-ca server and fills in the result
func (c *Client) SendReq(req *http.Request, result interface{}) (err error) {
	urlStr := req.URL.String()
	log.Debugf("Sending request %s", urlStr)

	err = c.Init()
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return errors.Wrapf(err, "%s failure of request: %s", req.Method, urlStr)
	}
	var respBody []byte
	if resp.Body != nil {
		respBody, err = ioutil.ReadAll(resp.Body)
		defer func() {
			err := resp.Body.Close()
			if err != nil {
				log.Debugf("Failed to close the response body: %s", err.Error())
			}
		}()
		if err != nil {
			return errors.Wrapf(err, "Failed to read response of request: %s", urlStr)
		}
	}
	var body *cfsslapi.Response
	if respBody != nil && len(respBody) > 0 {
		body = new(cfsslapi.Response)
		err = json.Unmarshal(respBody, body)
		if err != nil {
			return errors.Wrapf(err, "Failed to parse response: %s", respBody)
		}
		if len(body.Errors) > 0 {
			var errorMsg string
			for _, err := range body.Errors {
				msg := fmt.Sprintf("Response from server: Error code: %d - %s\n", err.Code, err.Message)
				if errorMsg == "" {
					errorMsg = msg
				} else {
					errorMsg = errorMsg + fmt.Sprintf("\n%s", msg)
				}
			}
			return errors.New(errorMsg)
		}
	}
	scode := resp.StatusCode
	if scode >= 400 {
		return errors.Errorf("Failed with server status code %d for request: \n%s", scode, urlStr)
	}
	if body == nil {
		return errors.Errorf("Empty response body: \n%s", urlStr)
	}
	if !body.Success {
		return errors.Errorf("Server returned failure for request: \n%s", urlStr)
	}
	log.Debugf("Response body result: %+v", body.Result)
	if result != nil {
		return mapstructure.Decode(body.Result, result)
	}
	return nil
}

// NewPost create a new post request
func (c *Client) newPost(endpoint string, reqBody []byte) (*http.Request, error) {
	curl, err := c.getURL(endpoint)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, curl, bytes.NewReader(reqBody))
	if err != nil {
		return nil, errors.Wrapf(err, "Failed posting to %s", curl)
	}
	return req, nil
}

func (c *Client) getURL(endpoint string) (string, error) {
	nurl, err := NormalizeURL(c.Config.URL)
	if err != nil {
		return "", err
	}
	rtn := fmt.Sprintf("%s/%s", nurl, endpoint)
	return rtn, nil
}

// newCertificateRequest creates a certificate request which is used to generate
// a CSR (Certificate Signing Request)
func (c *Client) newCertificateRequest(req *api.CSRInfo) *csr.CertificateRequest {
	cr := csr.CertificateRequest{}
	if req != nil && req.Names != nil {
		cr.Names = req.Names
	}
	if req != nil && req.Hosts != nil {
		cr.Hosts = req.Hosts
	} else {
		hostname, _ := os.Hostname()
		if hostname != "" {
			cr.Hosts = make([]string, 1)
			cr.Hosts[0] = hostname
		}
	}
	if req != nil && req.KeyRequest != nil {
		cr.KeyRequest = newCfsslBasicKeyRequest(req.KeyRequest)
	}
	if req != nil {
		cr.CA = req.CA
		cr.SerialNumber = req.SerialNumber
	}
	return &cr
}

func newCfsslBasicKeyRequest(bkr *api.BasicKeyRequest) *csr.BasicKeyRequest {
	return &csr.BasicKeyRequest{A: bkr.Algo, S: bkr.Size}
}

// NormalizeURL normalizes a URL (from cfssl)
func NormalizeURL(addr string) (*url.URL, error) {
	addr = strings.TrimSpace(addr)
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	if u.Opaque != "" {
		u.Host = net.JoinHostPort(u.Scheme, u.Opaque)
		u.Opaque = ""
	} else if u.Path != "" && !strings.Contains(u.Path, ":") {
		u.Host = net.JoinHostPort(u.Path, strconv.Itoa(config.DefaultServerPort))
		u.Path = ""
	} else if u.Scheme == "" {
		u.Host = u.Path
		u.Path = ""
	}
	if u.Scheme != "https" {
		u.Scheme = "http"
	}
	_, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		_, port, err = net.SplitHostPort(u.Host + ":" + strconv.Itoa(config.DefaultServerPort))
		if err != nil {
			return nil, err
		}
	}
	if port != "" {
		_, err = strconv.Atoi(port)
		if err != nil {
			return nil, err
		}
	}
	return u, nil
}

func storeCAChain(config *config.ClientConfig, profile string, si *api.GetCAInfoResponse) error {
	serverURL, err := url.Parse(config.URL)
	if err != nil {
		return err
	}
	fname := serverURL.Host
	if config.CAName != "" {
		fname = fmt.Sprintf("%s-%s", fname, config.CAName)
	}
	fname = strings.Replace(fname, ":", "-", -1)
	fname = strings.Replace(fname, ".", "-", -1) + ".pem"
	tlsfname := fmt.Sprintf("tls-%s", fname)

	rootCACertsDir := filepath.Join(config.CSPDir, "cacerts")
	intCACertsDir := filepath.Join(config.CSPDir, "intermediatecerts")
	tlsRootCACertsDir := filepath.Join(config.CSPDir, "tlscacerts")
	tlsIntCACertsDir := filepath.Join(config.CSPDir, "tlsintermediatecerts")

	var rootBlks [][]byte
	var intBlks [][]byte
	chain := si.CAChain
	for len(chain) > 0 {
		var block *pem.Block
		block, chain = pem.Decode(chain)
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return errors.Wrap(err, "Failed to parse certificate in the CA chain")
		}
		if !cert.IsCA {
			return errors.New("A certificate in the CA chain is not a CA certificate")
		}

		if len(cert.AuthorityKeyId) == 0 || bytes.Equal(cert.AuthorityKeyId, cert.SubjectKeyId) {
			rootBlks = append(rootBlks, pem.EncodeToMemory(block))
		} else {
			intBlks = append(intBlks, pem.EncodeToMemory(block))
		}
	}

	certBytes := bytes.Join(rootBlks, []byte(""))
	if len(certBytes) > 0 {
		if profile == "tls" {
			err = storeToFile("TLS root CA certificate", tlsRootCACertsDir, tlsfname, certBytes)
			if err != nil {
				return err
			}
		} else {
			err = storeToFile("root CA certificate", rootCACertsDir, fname, certBytes)
			if err != nil {
				return err
			}
		}
	}

	certBytes = bytes.Join(intBlks, []byte(""))
	if len(certBytes) > 0 {
		if profile == "tls" {
			err = storeToFile("TLS intermediate CA certificates", tlsIntCACertsDir, tlsfname, certBytes)
			if err != nil {
				return err
			}
		} else {
			err = storeToFile("intermediate CA certificates", intCACertsDir, tlsfname, certBytes)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func storeToFile(what, dir, fname string, contents []byte) error {
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return errors.Wrapf(err, "Failed to create directory for %s at '%s'", what, dir)
	}
	fpath := filepath.Join(dir, fname)
	err = util.WriteFile(fpath, contents, 0644)
	if err != nil {
		return errors.Wrapf(err, "Failed to store %s at '%s'", what, fpath)
	}
	log.Infof("Stored %s at %s", what, fpath)
	return nil
}
