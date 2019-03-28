package util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
	"github.com/pkg/errors"
	"github.com/rkcloudchain/cccsp"
	"github.com/rkcloudchain/cccsp/importer"
	"github.com/rkcloudchain/cccsp/keygen"
	"github.com/rkcloudchain/cccsp/provider"
	"github.com/rkcloudchain/cccsp/util"
)

// InitCCCSP initializes CCCSP
func InitCCCSP(path string) (cccsp.CCCSP, error) {
	if !filepath.IsAbs(path) {
		var err error
		path, err = filepath.Abs(path)
		if err != nil {
			return nil, err
		}
	}

	ks, err := provider.NewFileKEyStore(path)
	if err != nil {
		return nil, err
	}

	return provider.New(ks), nil
}

// ImportCCCSPKeyFromPEM attempts to create a private CCCSP key from a pem file keyFile
func ImportCCCSPKeyFromPEM(keyFile string, csp cccsp.CCCSP, temporary bool) (cccsp.Key, error) {
	keyBuffer, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	key, err := util.PEMToPrivateKey(keyBuffer)
	if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("Failed parsing private key from %s", keyFile))
	}
	switch key.(type) {
	case *ecdsa.PrivateKey:
		priv, err := util.PrivateKeyToDER(key.(*ecdsa.PrivateKey))
		if err != nil {
			return nil, errors.WithMessage(err, fmt.Sprintf("Failed to convert ECDSA private key for '%s'", keyFile))
		}
		sk, err := csp.KeyImport(priv, importer.ECDSAPRIKEY, temporary)
		if err != nil {
			return nil, errors.WithMessage(err, fmt.Sprintf("Failed to import ECDSA private key for '%s'", keyFile))
		}
		return sk, nil
	case *rsa.PrivateKey:
		return nil, errors.Errorf("Failed to import RSA key from %s; RSA private key import is not supported", keyFile)
	default:
		return nil, errors.Errorf("Failed to import key from %s: invalid secret key type", keyFile)
	}
}

// GetSignerFromCertFile load skifile and load private key represented by ski and return cccsp signer that conforms to crypto.Signer
func GetSignerFromCertFile(certFile string, csp cccsp.CCCSP) (cccsp.Key, crypto.Signer, *x509.Certificate, error) {
	certBytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "Could not read certificate file '%s'", certFile)
	}

	parsedCA, err := helpers.ParseCertificatePEM(certBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	key, cspSigner, err := GetSignerFromCert(parsedCA, csp)
	return key, cspSigner, parsedCA, err
}

// GetSignerFromCert load private key represented by ski and return cccsp signer that conforms to crypto.Signer
func GetSignerFromCert(cert *x509.Certificate, csp cccsp.CCCSP) (cccsp.Key, crypto.Signer, error) {
	if csp == nil {
		return nil, nil, errors.New("CSP was not initialized")
	}

	certPubK, err := csp.KeyImport(cert, importer.X509CERT, true)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "Failed to import certificate's public key")
	}

	ski := certPubK.Identifier()
	privateKey, err := csp.GetKey(ski)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "Could not find matching private key for SKI")
	}

	if !privateKey.Private() {
		return nil, nil, errors.Errorf("The private key associated with the certificate with SKI '%s' was not found", hex.EncodeToString(ski))
	}

	signer, err := provider.NewSigner(csp, privateKey)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "Failed to create signer from cccsp")
	}
	return privateKey, signer, nil
}

// LoadX509KeyPair reads and parses a public/private key pair from a pair of files.
func LoadX509KeyPair(certFile, keyFile string, csp cccsp.CCCSP) (*tls.Certificate, error) {
	certPEMBlock, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{}
	var skippedBlockTypes []string
	for {
		var certDERBlock *pem.Block
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		} else {
			skippedBlockTypes = append(skippedBlockTypes, certDERBlock.Type)
		}
	}

	if len(cert.Certificate) == 0 {
		if len(skippedBlockTypes) == 0 {
			return nil, errors.Errorf("Failed to find PEM block in file %s", certFile)
		}
		if len(skippedBlockTypes) == 1 && strings.HasSuffix(skippedBlockTypes[0], "PRIVATE KEY") {
			return nil, errors.Errorf("Failed to find certificate PEM data in file %s, but did find a private key; PEM inputs may have been switched", certFile)
		}
		return nil, errors.Errorf("Failed to find \"CERTIFICATE\" PEM block in file %s after skipping PEM blocks of the following types: %v", certFile, skippedBlockTypes)
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}

	_, cert.PrivateKey, err = GetSignerFromCert(x509Cert, csp)
	if err != nil {
		if keyFile != "" {
			log.Debugf("Could not load TLS certificate with CCCSP: %s", err)
			log.Debugf("Attempting fallback with certfile %s and keyfile %s", certFile, keyFile)
			fallbackCerts, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, errors.Wrapf(err, "Could not get the private key %s that matches %s", keyFile, certFile)
			}
			cert = &fallbackCerts
		} else {
			return nil, errors.WithMessage(err, "Could not load TLS certificate with CCCSP")
		}
	}

	return cert, nil
}

// CCCSPKeyRequestGenerate generates keys through CCCSP
// somewhat mirroring to cfssl/req.KeyRequest.Generate()
func CCCSPKeyRequestGenerate(req *csr.CertificateRequest, csp cccsp.CCCSP) (cccsp.Key, crypto.Signer, error) {
	log.Infof("generating key %+v", req.KeyRequest)
	algorithm, err := getCCCSPKeyGenAlgo(req.KeyRequest)
	if err != nil {
		return nil, nil, err
	}
	key, err := csp.KeyGenerate(string(algorithm), false)
	if err != nil {
		return nil, nil, err
	}
	cspSigner, err := provider.NewSigner(csp, key)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "Failed initializing CryptoSigner")
	}
	return key, cspSigner, nil
}

// getCCCSPKeyGenAlgo generates a key as specified in the request.
// This supports ECDSA and RSA
func getCCCSPKeyGenAlgo(kr csr.KeyRequest) (opts string, err error) {
	if kr == nil {
		return keygen.ECDSA256, nil
	}
	log.Debugf("generate key from request: algo=%s, size=%d", kr.Algo(), kr.Size())
	switch kr.Algo() {
	case "rsa":
		switch kr.Size() {
		case 2048:
			return keygen.RSA2048, nil
		case 3072:
			return keygen.RSA3072, nil
		case 4096:
			return keygen.RSA4096, nil
		default:
			return "", errors.Errorf("Invalid RSA key size: %d", kr.Size())
		}
	case "ecdsa":
		switch kr.Size() {
		case 256:
			return keygen.ECDSA256, nil
		case 384:
			return keygen.ECDSA384, nil
		case 521:
			return keygen.ECDSA521, nil
		default:
			return "", errors.Errorf("Invalid ECDSA key size: %d", kr.Size())
		}
	default:
		return "", errors.Errorf("Invalid algorithm: %s", kr.Algo())
	}
}

// CCCSPBackedSigner attempts to create a signer using csp cccsp.CCCSP.
func CCCSPBackedSigner(caFile, keyFile string, policy *config.Signing, csp cccsp.CCCSP) (signer.Signer, error) {
	_, cspSigner, parsedCA, err := GetSignerFromCertFile(caFile, csp)
	if err != nil {
		log.Debugf("No key found in CCCSP keystore, attempting fallback")
		var key cccsp.Key
		var signer crypto.Signer

		key, err = ImportCCCSPKeyFromPEM(keyFile, csp, false)
		if err != nil {
			return nil, errors.WithMessage(err, fmt.Sprintf("Could not find the private key in CCCSP keystore nor in keyfile '%s'", keyFile))
		}

		signer, err = provider.NewSigner(csp, key)
		if err != nil {
			return nil, errors.WithMessage(err, "Failed initializing CryptoSigner")
		}
		cspSigner = signer
	}

	signer, err := local.NewSigner(cspSigner, parsedCA, signer.DefaultSigAlgo(cspSigner), policy)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create new signer")
	}
	return signer, nil
}
