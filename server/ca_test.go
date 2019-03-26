package server

import (
	"crypto/x509"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/cfssl/log"
	"github.com/rkcloudchain/rksync-ca/config"
	"github.com/rkcloudchain/rksync-ca/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var backDatedCert = `Certificate:
Data:
	Version: 3 (0x2)
	Serial Number: 18237722559857237339 (0xfd19680a646b1d5b)
Signature Algorithm: ecdsa-with-SHA256
	Issuer: C=US, ST=NC, L=RTP, O=IBM, O=Hyperledger, OU=FVT, CN=ec256Key
	Validity
		Not Before: Jan  1 00:00:00 2037 GMT
		Not After : Jan  1 00:00:00 2037 GMT
	Subject: C=US, ST=NC, L=RTP, O=IBM, O=Hyperledger, OU=FVT, CN=intCaEc256
	Subject Public Key Info:
		Public Key Algorithm: id-ecPublicKey
			Public-Key: (256 bit)
			pub: 
				04:76:47:59:83:35:c2:2d:78:36:72:99:9a:3d:4f:
				c5:56:3c:a8:d6:cb:b1:77:df:96:24:d9:d7:20:68:
				96:a8:52:72:ef:74:e3:13:f1:15:7b:87:d0:4c:2d:
				87:07:ed:69:59:52:43:f1:e8:4a:9b:f4:17:fb:8c:
				b5:ea:12:52:cd
			ASN1 OID: prime256v1
	X509v3 extensions:
		X509v3 CRL Distribution Points: 

			Full Name:
			  URI:http://localhost:3755/ec256-1/crl/crl.der

		X509v3 Subject Key Identifier: 
			EC:7A:52:F4:3F:55:3A:7B:7C:47:7E:2F:8B:24:8E:22:8F:6E:65:97
		X509v3 Authority Key Identifier: 
			keyid:14:39:40:E4:8C:2C:2C:C7:A4:AB:21:48:45:B5:BA:EB:9D:18:50:26
			DirName:/C=US/ST=NC/L=RTP/O=IBM/O=Hyperledger/OU=FVT/CN=ec256Key
			serial:FD:19:68:0A:64:6B:1D:56

		X509v3 Basic Constraints: critical
			CA:TRUE
		X509v3 Key Usage: 
			Certificate Sign, CRL Sign
		X509v3 Certificate Policies: 
			Policy: X509v3 Any Policy

		X509v3 Subject Alternative Name: 
			IP Address:127.0.0.1
Signature Algorithm: ecdsa-with-SHA256
	 30:44:02:20:16:e1:a1:fb:fe:31:45:6b:59:f7:0f:6e:f7:9b:
	 1b:68:a8:94:93:c6:d1:12:dc:51:b2:12:7f:86:b2:3f:0f:98:
	 02:20:4c:ae:6a:5d:c4:f4:6f:5c:44:74:6c:33:90:66:41:2e:
	 2a:40:d0:c7:d8:8f:4d:e6:65:9b:2d:01:0d:04:f3:f5
-----BEGIN CERTIFICATE-----
MIIDGzCCAsKgAwIBAgIJAP0ZaApkax1bMAoGCCqGSM49BAMCMG0xCzAJBgNVBAYT
AlVTMQswCQYDVQQIEwJOQzEMMAoGA1UEBxMDUlRQMQwwCgYDVQQKEwNJQk0xFDAS
BgNVBAoTC0h5cGVybGVkZ2VyMQwwCgYDVQQLEwNGVlQxETAPBgNVBAMTCGVjMjU2
S2V5MCIYDzIwMzcwMTAxMDAwMDAwWhgPMjAzNzAxMDEwMDAwMDBaMG8xCzAJBgNV
BAYTAlVTMQswCQYDVQQIEwJOQzEMMAoGA1UEBxMDUlRQMQwwCgYDVQQKEwNJQk0x
FDASBgNVBAoTC0h5cGVybGVkZ2VyMQwwCgYDVQQLEwNGVlQxEzARBgNVBAMTCmlu
dENhRWMyNTYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR2R1mDNcIteDZymZo9
T8VWPKjWy7F335Yk2dcgaJaoUnLvdOMT8RV7h9BMLYcH7WlZUkPx6Eqb9Bf7jLXq
ElLNo4IBQzCCAT8wOgYDVR0fBDMwMTAvoC2gK4YpaHR0cDovL2xvY2FsaG9zdDoz
NzU1L2VjMjU2LTEvY3JsL2NybC5kZXIwHQYDVR0OBBYEFOx6UvQ/VTp7fEd+L4sk
jiKPbmWXMIGfBgNVHSMEgZcwgZSAFBQ5QOSMLCzHpKshSEW1uuudGFAmoXGkbzBt
MQswCQYDVQQGEwJVUzELMAkGA1UECBMCTkMxDDAKBgNVBAcTA1JUUDEMMAoGA1UE
ChMDSUJNMRQwEgYDVQQKEwtIeXBlcmxlZGdlcjEMMAoGA1UECxMDRlZUMREwDwYD
VQQDEwhlYzI1NktleYIJAP0ZaApkax1WMA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0P
BAQDAgEGMBEGA1UdIAQKMAgwBgYEVR0gADAPBgNVHREECDAGhwR/AAABMAoGCCqG
SM49BAMCA0cAMEQCIBbhofv+MUVrWfcPbvebG2iolJPG0RLcUbISf4ayPw+YAiBM
rmpdxPRvXER0bDOQZkEuKkDQx9iPTeZlmy0BDQTz9Q==
-----END CERTIFICATE-----
`

var expiredCert = `-----BEGIN CERTIFICATE-----
MIIFpzCCA4+gAwIBAgIJAPckH7nSDuuVMA0GCSqGSIb3DQEBCwUAMGoxCzAJBgNV
BAYTAlVTMRcwFQYDVQQIDA5Ob3J0aCBDYXJvbGluYTEQMA4GA1UEBwwHUmFsZWln
aDEMMAoGA1UECgwDSUJNMRMwEQYDVQQLDApCbG9ja2NoYWluMQ0wCwYDVQQDDARz
YWFkMB4XDTE3MDMyMTE0MTkwNFoXDTE3MDMyMjE0MTkwNFowajELMAkGA1UEBhMC
VVMxFzAVBgNVBAgMDk5vcnRoIENhcm9saW5hMRAwDgYDVQQHDAdSYWxlaWdoMQww
CgYDVQQKDANJQk0xEzARBgNVBAsMCkJsb2NrY2hhaW4xDTALBgNVBAMMBHNhYWQw
ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDRLs+jael13J9ieGL2q6XU
iMbgd/YUTnPVpdFAXIEJCcRBB25/5e6jQXbevUXG/QIl3HBv9YYmtXKaQZLeL4TO
JTdCHMMGOKaB+foGPDeXLSibn9FTBYMJd5fjC2c5cdL/8vjSMlV0BRpiWfeixJgO
g/o/qvGxOz74S5EWPj7ox8HjfO8epadiaZ58INAuFGRjOzMwy1aDMYj/CUR80/O4
9SmLDdMbeceZqvE5iCSx08Eu1e+kjysvTqt5B7K2NqEsOqX0bBb6ViOLTD2nnGfQ
MVDtpJGirvV1s/rYauTfoU0CF3/pO7y/QZFukE1Kp+wHx/SGjZU5974hGgFPF9BQ
R77ei5Sh9sNw9ia5IqRirRpOOsCTqiRwiE3guhLdvuPL7TsLashMBSqq0yjdSCIz
I3aZCY/qkh6TgCjoztuuHaoaAsF9iCWO2jlbI963omV+inmRaiQIDu9UlhygG3XY
qGNh1Ue7rbSK/lNiLDRnxDYCgT7OZ7JYhIZZNoyGSQHx+Y4qQnWevAE7F1ysTtHi
824Zbjz2bmbqZq1RVLQ0mTZ9IUGTnftPe8LVBUhKbTGHsjQaT4Qm0pocnPSw9bg7
MBraYMEDvQjp/ME6KDhpNbDbPsaKvwz3XbqP7/KFkWNhFJjntfcT7RGU15bC1xJA
63USl5IY8nFwGIN18RVBDQIDAQABo1AwTjAdBgNVHQ4EFgQUtKsl77wYVhKatmIg
D0SdCKxnPV8wHwYDVR0jBBgwFoAUtKsl77wYVhKatmIgD0SdCKxnPV8wDAYDVR0T
BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEAeU9L+mfT1Id7K5ve/sbZ9Uh1vSZu
oWU7EpZsAvUX6TEWL4Mjuf7Z1heSirgYwP9TYy/s6cjsKbuJyqvnD9pn8LIDAwVc
KTWwyK3PL74OtgC5k9M4WJYsolHuSWxvrbYpWI8NFi9H84H9og+I9yEhY4chzc/P
W7VWKkAZT8HwsZi1+aipS8jREDEI+g9MUiOnjCWYaK0C13czjeAQ9eV5wZ5WVrOR
mtCWBHDSoN2QMgyV5SrMyN47hBPmyiku06XIdPNOIGBeucvUduFr6xo9Mn2b1WZa
HW0pnqeG6yQzpzIujPPepg4/D4JIASSxzfhoAri2dpGzAPaa1VY9zsDkSOWsdDxy
GmOjDdF8j2fwjXvn2nwOmVKgQaxcpzJ7Dz6o5EK6pQvo6O4GrdSvAii9jDlbDY7i
N+qB8f7VJ3xXLBoKiiqoklYwRjRaEhIiym+BmiOh/EYVIXsU9pe5opPWNMhUnbI6
FBlCxea5tO04GLhMGuSh1SyCbBx+XbzMv3PBpORcDshV11yjb7xiyJJk/L2b82bO
Debwe/HBflcFCzQSwYKsZ/WdmRkKZbKgUvy6/JIEz/mvFsK2nJZBK1orQHNJPS09
kgVh172RqWg0r4lXUVH96xxVIAsoZ/zphQ3gPPXq/MtKw7geAcNicCKKbWPLUKdv
PYm9fooFAN1mGcg=
-----END CERTIFICATE-----
`

func TestCABadCertificates(t *testing.T) {
	home, err := filepath.Abs("../testdata")
	require.NoError(t, err)

	dirClean(t)

	ca, err := newCA(home, &config.CAConfig{}, true)
	require.NoError(t, err)

	err = ca.validateCertAndKey("../testdata/caFalse.cert.pem", "../testdata/caFalse.key.pem")
	assert.Error(t, err)

	err = ca.validateCertAndKey("../testdata/tls-client.cert.pem", "../testdata/tls-client.key.pem")
	assert.Error(t, err)

	cert, err := util.GetX509CertificateFromPEM([]byte(backDatedCert))
	require.NoError(t, err)
	err = validateDates(cert)
	assert.Error(t, err)

	cert, err = util.GetX509CertificateFromPEM([]byte(expiredCert))
	require.NoError(t, err)
	err = validateDates(cert)
	assert.Error(t, err)

	err = validateKeyType(cert)
	assert.NoError(t, err)

	err = validateKeySize(cert)
	assert.NoError(t, err)

	err = validateUsage(cert, "")
	assert.Error(t, err)

	err = ca.closeDB()
	assert.NoError(t, err)
	dirClean(t)
}

func TestMatchingKeys(t *testing.T) {
	cert, err := getCertFromFile("../testdata/ec.pem")
	require.NoError(t, err)

	err = validateMatchingKeys(cert, "../testdata/ec-key.pem")
	assert.NoError(t, err)

	err = validateMatchingKeys(cert, "../testdata/ec-not-matching-key.pem")
	assert.Error(t, err)

	cert, err = getCertFromFile("../testdata/rsa.pem")
	require.NoError(t, err)

	err = validateMatchingKeys(cert, "../testdata/rsa-key.pem")
	assert.NoError(t, err)

	err = validateMatchingKeys(cert, "../testdata/rsa-not-matching-key.pem")
	assert.Error(t, err)

	err = validateMatchingKeys(cert, string(0))
	assert.Error(t, err)
}

func getCertFromFile(f string) (*x509.Certificate, error) {
	p, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return util.GetX509CertificateFromPEM(p)
}

func newCA(home string, config *config.CAConfig, renew bool) (*CA, error) {
	ca := new(CA)
	err := initCA(ca, home, config, renew)
	if err != nil {
		err2 := ca.closeDB()
		if err2 != nil {
			log.Errorf("Close DB failed: %s", err2)
		}
		return nil, err
	}
	return ca, nil
}

func dirClean(t *testing.T) {
	err := os.RemoveAll(filepath.Join("../testdata", "csp"))
	if err != nil {
		t.Fatalf("RemoveAll failed: %s", err)
	}

	err = os.RemoveAll(filepath.Join("../testdata", "ca-cert.pem"))
	if err != nil {
		t.Fatalf("RemoveAll failed: %s", err)
	}

	err = os.RemoveAll(filepath.Join("../testdata", "ca-key.pem"))
	if err != nil {
		t.Fatalf("RemoveAll failed: %s", err)
	}
}
