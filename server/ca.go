package server

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	cfcfg "github.com/cloudflare/cfssl/config"
	cfcsr "github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
	"github.com/pkg/errors"
	"github.com/rkcloudchain/cccsp"
	"github.com/rkcloudchain/rksync-ca/api"
	"github.com/rkcloudchain/rksync-ca/api/registry"
	"github.com/rkcloudchain/rksync-ca/attrmgr"
	"github.com/rkcloudchain/rksync-ca/client"
	"github.com/rkcloudchain/rksync-ca/config"
	dbutil "github.com/rkcloudchain/rksync-ca/db"
	caerrors "github.com/rkcloudchain/rksync-ca/errors"
	"github.com/rkcloudchain/rksync-ca/metadata"
	"github.com/rkcloudchain/rksync-ca/util"
)

const (
	certificateError = "Invalid certificate in file"

	// CAChainParentFirstEnvVar is the name of the environment variable that needs to be set
	// for server to return CA chain in parent-first order
	CAChainParentFirstEnvVar = "CA_CHAIN_PARENT_FIRST"
)

var (
	// Default root CA certificate expiration is 15 years (in hours).
	defaultRootCACertificateExpiration = "131400h"

	// Default intermediate CA certificate expiration is 5 years (in hours).
	defaultIntermediateCACertificateExpiration = parseDuration("43800h")

	// Default issued certificate expiration is 1 year (in hours).
	defaultIssuedCertificateExpiration = parseDuration("8760h")
)

// CA represents a certificate authority which signs, issues and revokes certificates
type CA struct {
	// The home directory for the CA
	HomeDir string
	// The CA's configuration
	Config *config.CAConfig
	// The signer used for enrollment
	enrollSigner signer.Signer
	// The attribute manager
	attrMgr *attrmgr.Mgr
	// The crypto service provider (CCCSP)
	csp cccsp.CCCSP
	// The database handle used to store certificate and optionally
	// the user registry information
	db *dbutil.DB
	// The certificate DB accessor
	certDBAccessor *CertDBAccessor
	// The user registry
	registry registry.UserRegistry
	// CA mutex
	mutex sync.Mutex
}

// initCA will initialize the passed in pointer to a CA struct
func initCA(ca *CA, homeDir string, config *config.CAConfig, renew bool) error {
	ca.HomeDir = homeDir
	ca.Config = config

	return ca.init(renew)
}

// Init initializes an instance of a CA
func (ca *CA) init(renew bool) (err error) {
	log.Debugf("Init CA with home %s and config %+v", ca.HomeDir, *ca.Config)

	err = ca.initConfig()
	if err != nil {
		return err
	}

	ca.csp, err = util.InitCCCSP("csp", ca.HomeDir)
	if err != nil {
		return err
	}

	err = ca.initKeyMaterial(renew)
	if err != nil {
		return err
	}

	err = ca.initDB()
	if err != nil {
		log.Errorf("Error occurred initializing database: %s", err)
		if caerrors.IsFatalError(err) {
			return err
		}
	}

	err = ca.initEnrollmentSigner()
	if err != nil {
		return err
	}

	return nil
}

// Initialize the configuration for the CA setting any defaults and making filenams absolute
func (ca *CA) initConfig() (err error) {
	if ca.HomeDir == "" {
		ca.HomeDir, err = os.Getwd()
		if err != nil {
			return errors.Wrap(err, "Failed to initialize CA's home directory")
		}
	}
	log.Debugf("CA Home Directory: %s", ca.HomeDir)

	if ca.Config == nil {
		ca.Config = new(config.CAConfig)
		ca.Config.Registry.MaxEnrollments = -1
	}

	cfg := ca.Config
	if cfg.Version == "" {
		cfg.Version = "0"
	}
	if cfg.CA.Certfile == "" {
		cfg.CA.Certfile = "ca-cert.pem"
	}
	if cfg.CA.Keyfile == "" {
		cfg.CA.Keyfile = "ca-key.pem"
	}
	if cfg.CA.Chainfile == "" {
		cfg.CA.Chainfile = "ca-chain.pem"
	}
	if cfg.CSR.CA == nil {
		cfg.CSR.CA = &cfcsr.CAConfig{}
	}
	if cfg.CSR.CA.Expiry == "" {
		cfg.CSR.CA.Expiry = defaultRootCACertificateExpiration
	}
	if cfg.Signing == nil {
		cfg.Signing = &cfcfg.Signing{}
	}
	cs := cfg.Signing
	if cs.Profiles == nil {
		cs.Profiles = make(map[string]*cfcfg.SigningProfile)
	}
	if cfg.CSP == nil {
		cfg.CSP = &config.CSP{SecLevel: 256}
	}

	caProfile := cs.Profiles["ca"]
	initSigningProfile(&caProfile, defaultIntermediateCACertificateExpiration, true)
	cs.Profiles["ca"] = caProfile
	initSigningProfile(&cs.Default, defaultIssuedCertificateExpiration, false)
	tlsProfile := cs.Profiles["tls"]
	initSigningProfile(&tlsProfile, defaultIssuedCertificateExpiration, false)
	cs.Profiles["tls"] = tlsProfile

	err = ca.checkConfigLevels()
	if err != nil {
		return err
	}
	ca.normalizeStringSlices()
	return nil
}

// Initialize the CA's key material
func (ca *CA) initKeyMaterial(renew bool) error {
	log.Debug("Initialize key material")

	err := ca.makeFileNamesAbsolute()
	if err != nil {
		return err
	}

	keyFile := ca.Config.CA.Keyfile
	certFile := ca.Config.CA.Certfile

	if !renew {
		keyFileExists := util.FileExists(keyFile)
		certFileExists := util.FileExists(certFile)
		if keyFileExists && certFileExists {
			log.Info("The CA key and certificate files already exists")
			log.Infof("Key file location: %s", keyFile)
			log.Infof("Certificate file location: %s", certFile)
			err = ca.validateCertAndKey(certFile, keyFile)
			if err != nil {
				return errors.WithMessage(err, "Validation of certificate and key failed")
			}

			ca.Config.CSR.CN, err = ca.loadCNFromEnrollmentInfo(certFile)
			if err != nil {
				return err
			}
			return nil
		}

		if certFileExists {
			_, _, _, err = util.GetSignerFromCertFile(certFile, ca.csp)
			if err != nil {
				return errors.WithMessage(err, fmt.Sprintf("Failed to find private key for certificate in '%s'", certFile))
			}

			log.Info("The CA key and certificate already exists")
			log.Infof("The certificate is at: %s", certFile)

			ca.Config.CSR.CN, err = ca.loadCNFromEnrollmentInfo(certFile)
			if err != nil {
				return errors.WithMessage(err, fmt.Sprintf("Failed to get CN for certificate in '%s'", certFile))
			}
			return nil
		}
		log.Warningf("The specified CA certificate file %s does not exists", certFile)
	}

	cert, err := ca.getCACert()
	if err != nil {
		return err
	}

	err = util.WriteFile(certFile, cert, 0644)
	if err != nil {
		return errors.Wrap(err, "Failed to store certificate")
	}
	log.Infof("The CA key and certificate were generated for CA %s", ca.Config.CA.Name)
	log.Infof("The certificate is at: %s", certFile)

	return nil
}

// Initialize the dataase for the CA
func (ca *CA) initDB() error {
	log.Debug("Initializing DB")

	if ca.db != nil && ca.db.IsInitialized() {
		return nil
	}

	ca.mutex.Lock()
	defer ca.mutex.Unlock()

	if ca.db != nil && ca.db.IsInitialized() {
		return nil
	}

	db := &ca.Config.DB
	var err error

	if db.Type == "" || db.Datasource == "" {
		return errors.New("CA database configuration is not specified")
	}

	ds := dbutil.MakeDBCred(db.Datasource)
	log.Debugf("Initializing '%s' database at '%s'", db.Type, ds)

	switch db.Type {
	case "postgres":
		ca.db, err = dbutil.NewUserRegistryPostgres(db.Datasource)
		if err != nil {
			return errors.WithMessage(err, "Failed to create user registry for PostgresSQL")
		}
	case "mysql":
		ca.db, err = dbutil.NewUserRegistryMySQL(db.Datasource)
		if err != nil {
			return errors.WithMessage(err, "Failed to create user registry for MySQL")
		}
	default:
		return errors.Errorf("Invalid db.Type in config file: '%s', must be 'postgres' or 'mysql'", db.Type)
	}

	ca.certDBAccessor = NewCertDBAccessor(ca.db)
	if ca.enrollSigner != nil {
		ca.enrollSigner.SetDBAccessor(ca.certDBAccessor)
	}
	ca.initUserRegistry()

	ca.db.IsDBInitialized = true
	log.Infof("Initialized %s database at %s", db.Type, ds)
	return nil
}

// Initialize the user registry interface
func (ca *CA) initUserRegistry() {
	log.Debug("Initializing identity registry")
	dbAccessor := new(Accessor)
	dbAccessor.SetDB(ca.db)
	ca.registry = dbAccessor
	log.Debug("Initialized DB identity registry")
}

// Initialize the enrollment signer
func (ca *CA) initEnrollmentSigner() (err error) {
	log.Debug("Initializing enrollment signer")
	c := ca.Config

	var policy *cfcfg.Signing
	if c.Signing != nil {
		policy = c.Signing
	} else {
		policy = &cfcfg.Signing{
			Profiles: map[string]*cfcfg.SigningProfile{},
			Default:  cfcfg.DefaultConfig(),
		}
		policy.Default.CAConstraint.IsCA = true
	}

	parentServerURL := ca.Config.Intermediate.ParentServer.URL
	if parentServerURL != "" {
		err = policy.OverrideRemotes(parentServerURL)
		if err != nil {
			return errors.Wrap(err, "Failed initializing enrollment signer")
		}
	}

	ca.enrollSigner, err = util.CCCSPBackedSigner(c.CA.Certfile, c.CA.Keyfile, policy, ca.csp)
	if err != nil {
		return err
	}
	ca.enrollSigner.SetDBAccessor(ca.certDBAccessor)

	return nil
}

// Get the CA certificate for this CA
func (ca *CA) getCACert() (cert []byte, err error) {
	if ca.Config.Intermediate.ParentServer.URL != "" {
		log.Debugf("Getting CA cert; parent server URL is %s", util.GetMaskedURL(ca.Config.Intermediate.ParentServer.URL))
		clientCfg := ca.Config.Client
		if clientCfg == nil {
			clientCfg = &config.ClientConfig{}
		}
		clientCfg.TLS = ca.Config.Intermediate.TLS
		clientCfg.CAName = ca.Config.Intermediate.ParentServer.CAName
		clientCfg.CSR = ca.Config.CSR
		if ca.Config.CSR.CN != "" {
			return nil, errors.Errorf("CN '%s' cannot be sepcified for an intermediate CA. Remove CN from CSR section for enrollment of intermediate CA to be successful", ca.Config.CSR.CN)
		}

		var resp *api.EnrollmentResponse
		resp, err = ca.enroll(clientCfg, ca.Config.Intermediate.ParentServer.URL, ca.HomeDir)
		if err != nil {
			return nil, err
		}

		ca.Config.CSR.CN = resp.Identity.Name
		ecert := resp.Identity.GetECert()
		if ecert == nil {
			return nil, errors.New("No enrollment certificate returned by parent server")
		}
		cert = ecert.Cert()
		chainPath := ca.Config.CA.Chainfile
		chain, err := ca.concatChain(resp.CAInfo.CAChain, cert)
		if err != nil {
			return nil, err
		}
		err = os.MkdirAll(filepath.Dir(chainPath), 0755)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to create intermediate chain file directory")
		}
		err = util.WriteFile(chainPath, chain, 0644)
		if err != nil {
			return nil, errors.WithMessage(err, "Failed to create intermediate chain file")
		}
		log.Debugf("Stored intermediate certificate chain at %s", chainPath)
	} else {
		if ca.Config.CSR.CN == "" {
			ca.Config.CSR.CN = "rksync-ca"
		}
		csr := &ca.Config.CSR
		if csr.CA == nil {
			csr.CA = &cfcsr.CAConfig{}
		}
		if csr.CA.Expiry == "" {
			csr.CA.Expiry = defaultRootCACertificateExpiration
		}

		if csr.KeyRequest == nil || (csr.KeyRequest.Algo == "" && csr.KeyRequest.Size == 0) {
			csr.KeyRequest = GetKeyRequest(ca.Config)
		}
		req := cfcsr.CertificateRequest{
			CN:           csr.CN,
			Names:        csr.Names,
			Hosts:        csr.Hosts,
			KeyRequest:   &cfcsr.BasicKeyRequest{A: csr.KeyRequest.Algo, S: csr.KeyRequest.Size},
			CA:           csr.CA,
			SerialNumber: csr.SerialNumber,
		}
		log.Debugf("Root CA certificate request: %+v", req)
		_, cspSigner, err := util.CCCSPKeyRequestGenerate(&req, ca.csp)
		if err != nil {
			return nil, err
		}
		cert, _, err = initca.NewFromSigner(&req, cspSigner)
		if err != nil {
			return nil, errors.WithMessage(err, "Failed to create new CA certificate")
		}
	}
	return cert, nil
}

func (ca *CA) concatChain(chain []byte, cert []byte) ([]byte, error) {
	result := make([]byte, len(chain)+len(cert))
	parentFirst, ok := os.LookupEnv(CAChainParentFirstEnvVar)
	parentFirstBool := false

	if ok {
		var err error
		parentFirstBool, err = strconv.ParseBool(parentFirst)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to parse the environment variable '%s'", parentFirst)
		}
	}
	if parentFirstBool {
		copy(result[:len(chain)], chain)
		copy(result[len(chain):], cert)
	} else {
		copy(result[:len(cert)], cert)
		copy(result[len(cert):], chain)
	}
	return result, nil
}

func (ca *CA) enroll(cfg *config.ClientConfig, rawurl, home string) (*api.EnrollmentResponse, error) {
	purl, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}

	req := &api.EnrollmentRequest{}
	if purl.User != nil {
		name := purl.User.Username()
		secret, _ := purl.User.Password()
		req.Name = name
		req.Secret = secret
		purl.User = nil
	}
	if req.Name == "" {
		expecting := fmt.Sprintf("%s://<enrollmentID>:<secret>@%s", purl.Scheme, purl.Host)
		return nil, errors.Errorf("The URL of the rksync CA server is missing the enrollment ID and secret;"+" found '%s' but expecting '%s'", rawurl, expecting)
	}

	req.CAName = cfg.CAName
	cfg.URL = purl.String()
	cfg.TLS.Enabled = purl.Scheme == "https"
	req.CSR = &cfg.CSR
	req.Profile = "ca"
	client := &client.Client{HomeDir: home, Config: cfg}
	return client.Enroll(req)
}

// Load CN from existing enrollment information
func (ca *CA) loadCNFromEnrollmentInfo(certFile string) (string, error) {
	log.Debug("Loading CN from existing enrollment information")

	cert, err := ioutil.ReadFile(certFile)
	if err != nil {
		log.Debugf("No cert found at %s", certFile)
		return "", err
	}

	name, err := util.GetEnrollmentIDFromPEM(cert)
	if err != nil {
		return "", err
	}
	return name, nil
}

// Performs checks on the provided CA cert to make sure it's valid
func (ca *CA) validateCertAndKey(certFile string, keyFile string) error {
	log.Debug("Validating the CA certificate and key")
	var err error
	var certPEM []byte

	certPEM, err = ioutil.ReadFile(certFile)
	if err != nil {
		return errors.Wrapf(err, certificateError+" '%s'", certFile)
	}

	cert, err := util.GetX509CertificateFromPEM(certPEM)
	if err != nil {
		return errors.WithMessage(err, fmt.Sprintf(certificateError+" '%s'", certFile))
	}

	if err = validateDates(cert); err != nil {
		return errors.WithMessage(err, fmt.Sprintf(certificateError+" '%s'", certFile))
	}
	if err = validateUsage(cert, ca.Config.CA.Name); err != nil {
		return errors.WithMessage(err, fmt.Sprintf(certificateError+" '%s'", certFile))
	}
	if err = validateIsCA(cert); err != nil {
		return errors.WithMessage(err, fmt.Sprintf(certificateError+" '%s'", certFile))
	}
	if err = validateKeyType(cert); err != nil {
		return errors.WithMessage(err, fmt.Sprintf(certificateError+" '%s'", certFile))
	}
	if err = validateKeySize(cert); err != nil {
		return errors.WithMessage(err, fmt.Sprintf(certificateError+" '%s'", certFile))
	}
	if err = validateMatchingKeys(cert, keyFile); err != nil {
		return errors.WithMessage(err, fmt.Sprintf("Invalid certificate and/or key in files '%s' and '%s'", certFile, keyFile))
	}
	log.Debug("Validation of CA certificate and key successful")
	return nil
}

// Make all file names in the CA config absolute
func (ca *CA) makeFileNamesAbsolute() error {
	log.Debug("Making CA file names absolute")

	fields := []*string{&ca.Config.CA.Certfile, &ca.Config.CA.Keyfile, &ca.Config.CA.Chainfile}
	return util.MakeFileNamesAbsolute(fields, ca.HomeDir)
}

func validateDates(cert *x509.Certificate) error {
	log.Debug("Check CA certificate for valid dates")

	notAfter := cert.NotAfter
	currentTime := time.Now().UTC()

	if currentTime.After(notAfter) {
		return errors.New("Certificate provided has expired")
	}

	notBefore := cert.NotBefore
	if currentTime.Before(notBefore) {
		return errors.New("Certificate provided not valid until later date")
	}

	return nil
}

func validateUsage(cert *x509.Certificate, caname string) error {
	log.Debug("Check CA certificate for valid usages")

	if cert.KeyUsage == 0 {
		return errors.New("No usage specified for certificate")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("The 'cert sign' key usage is required")
	}
	if !canSignCRL(cert) {
		log.Warningf("The CA certificate for the CA '%s' does not have 'crl sign' key usage, so the CA will not be able to generate a CRL", caname)
	}
	return nil
}

func validateIsCA(cert *x509.Certificate) error {
	log.Debug("Check CA certificate for valid IsCA value")

	if !cert.IsCA {
		return errors.New("Certificate not configured to be used for CA")
	}

	return nil
}

func validateKeyType(cert *x509.Certificate) error {
	log.Debug("Check that key type is supported")

	switch cert.PublicKey.(type) {
	case *dsa.PublicKey:
		return errors.New("Unsupported key type: DSA")
	}

	return nil
}

func validateKeySize(cert *x509.Certificate) error {
	log.Debug("Check that key size is of appropriate length")

	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		size := cert.PublicKey.(*rsa.PublicKey).N.BitLen()
		if size < 2048 {
			return errors.New("Key size is less than 2048 bits")
		}
	}

	return nil
}

func validateMatchingKeys(cert *x509.Certificate, keyFile string) error {
	log.Debug("Check that public key and private key match")

	keyPEM, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return err
	}

	pubKey := cert.PublicKey
	switch pubKey.(type) {
	case *rsa.PublicKey:
		privKey, err := util.GetRSAPrivateKey(keyPEM)
		if err != nil {
			return err
		}

		if privKey.PublicKey.N.Cmp(pubKey.(*rsa.PublicKey).N) != 0 {
			return errors.New("Public key and private key do not match")
		}
	case *ecdsa.PublicKey:
		privKey, err := util.GetECPrivateKey(keyPEM)
		if err != nil {
			return err
		}

		if privKey.PublicKey.X.Cmp(pubKey.(*ecdsa.PublicKey).X) != 0 {
			return errors.New("Public key and private key do not match")
		}
	}

	return nil
}

func canSignCRL(cert *x509.Certificate) bool {
	return cert.KeyUsage&x509.KeyUsageCRLSign != 0
}

func parseDuration(str string) time.Duration {
	d, err := time.ParseDuration(str)
	if err != nil {
		panic(err)
	}
	return d
}

func initSigningProfile(spp **cfcfg.SigningProfile, expiry time.Duration, isCA bool) {
	sp := *spp
	if sp == nil {
		sp = &cfcfg.SigningProfile{CAConstraint: cfcfg.CAConstraint{IsCA: isCA}}
		*spp = sp
	}
	if sp.Usage == nil {
		sp.Usage = []string{"cert sign", "crl sign"}
	}
	if sp.Expiry == 0 {
		sp.Expiry = expiry
	}
	if sp.ExtensionWhitelist == nil {
		sp.ExtensionWhitelist = map[string]bool{}
	}

	sp.ExtensionWhitelist[attrmgr.AttrOIDString] = true
}

// This function returns on error if the version specified in the configuration file is greater than the server version
func (ca *CA) checkConfigLevels() error {
	var err error
	serverVersion := metadata.GetVersion()
	configVersion := ca.Config.Version
	log.Debugf("Checking configuration file version '%+v' against server version: '%+v'", configVersion, serverVersion)

	cmp, err := metadata.CmpVersion(configVersion, serverVersion)
	if err != nil {
		return errors.WithMessage(err, "Failed to compare version")
	}
	if cmp == -1 {
		return errors.Errorf("Configuration file version '%s' is higher than server version '%s'", configVersion, serverVersion)
	}
	return nil
}

func (ca *CA) normalizeStringSlices() {
	fields := []*[]string{
		&ca.Config.CSR.Hosts,
	}
	for _, namePtr := range fields {
		norm := util.NormalizeStringSlice(*namePtr)
		*namePtr = norm
	}
}

// Close CA's DB
func (ca *CA) closeDB() error {
	if ca.db != nil {
		err := ca.db.Close()
		ca.db = nil
		if err != nil {
			return errors.Wrapf(err, "Failed to close CA database, where CA home directory is '%s'", ca.HomeDir)
		}
	}
	return nil
}

// Returns expiration of the CA certificate
func (ca *CA) getCACertExpiry() (time.Time, error) {
	var caexpiry time.Time
	signer, ok := ca.enrollSigner.(*local.Signer)
	if ok {
		cacert, err := signer.Certificate("", "ca")
		if err != nil {
			log.Errorf("Failed to get CA certificate for CA %s: %s", ca.Config.CA.Name, err)
			return caexpiry, err
		} else if cacert != nil {
			caexpiry = cacert.NotAfter
		}
	} else {
		log.Errorf("Not expected condition as the enrollSigner can only be cfssl/signer/local/Signer")
		return caexpiry, errors.New("Unexpected error while getting CA certificate expiration")
	}
	return caexpiry, nil
}

// Returns nil error and the value of the attribute
// if the user has the attribute, or an appropriate error if the user
// does not have this attribute
func (ca *CA) userHasAttribute(username, attrname string) (string, error) {
	val, err := ca.getUserAttrValue(username, attrname)
	if err != nil {
		return "", err
	}
	if val == "" {
		return "", errors.Errorf("Identity '%s' does not have attribute '%s'", username, attrname)
	}
	return val, nil
}

// Returns nil if the attribute has one of the following values:
// "1", "t", "T", "true", "TRUE", "True"
func (ca *CA) attributeIsTrue(username, attrname string) error {
	val, err := ca.userHasAttribute(username, attrname)
	if err != nil {
		return err
	}
	val2, err := strconv.ParseBool(val)
	if err != nil {
		return errors.Wrapf(err, "Invalid value for attribute '%s' of identity '%s'", attrname, username)
	}
	if val2 {
		return nil
	}
	return errors.Errorf("Attribute '%s' is not set to true for identity '%s'", attrname, username)
}

// Returns a user's value for an attribute
func (ca *CA) getUserAttrValue(username, attrname string) (string, error) {
	log.Debugf("Get user attribute value, identity=%s, attr=%s", username, attrname)
	user, err := ca.registry.GetUser(username, []string{attrname})
	if err != nil {
		return "", err
	}
	attrval, err := user.GetAttribute(attrname)
	if err != nil {
		return "", errors.WithMessage(err, fmt.Sprintf("Failed to get attribute '%s' for user '%s'", attrname, user.GetName()))
	}
	log.Debugf("Get user attribute value, identity=%s, name=%s, value=%s", username, attrname, attrval)
	return attrval.Value, nil
}

// Fills the CA info structure appropriately
func (ca *CA) fillCAInfo(info *api.CAInfoResponseNet) error {
	caChain, err := ca.getCAChain()
	if err != nil {
		return err
	}
	info.CAName = ca.Config.CA.Name
	info.CAChain = base64.StdEncoding.EncodeToString(caChain)
	info.Version = metadata.GetVersion()
	return nil
}

// Get the certificate chain for the CA
func (ca *CA) getCAChain() (chain []byte, err error) {
	if ca.Config == nil {
		return nil, errors.New("The server has no configuration")
	}
	certAuth := &ca.Config.CA
	if util.FileExists(certAuth.Chainfile) {
		return ioutil.ReadFile(certAuth.Chainfile)
	}

	if ca.Config.Intermediate.ParentServer.URL == "" {
		return ioutil.ReadFile(certAuth.Certfile)
	}

	return nil, errors.Errorf("Chain file does not exist at %s", certAuth.Chainfile)
}
