package util_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"testing"

	"github.com/rkcloudchain/rksync-ca/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileExists(t *testing.T) {
	name := "../README.md"
	exists := util.FileExists(name)
	assert.True(t, exists)

	name = "file-not-exists"
	exists = util.FileExists(name)
	assert.False(t, exists)
}

func TestMakeFilesAbs(t *testing.T) {
	file1 := "a"
	file2 := "a/b"
	file3 := "/a/b"
	files := []*string{&file1, &file2, &file3}
	err := util.MakeFileNamesAbsolute(files, "/tmp")
	require.NoError(t, err)

	assert.Equal(t, "/tmp/a", file1)
	assert.Equal(t, "/tmp/a/b", file2)
	assert.Equal(t, "/a/b", file3)
}

func TestMakeFileAbs(t *testing.T) {
	testMakeFileAbs(t, "", "", "")
	testMakeFileAbs(t, "/a/b/c", "", "/a/b/c")
	testMakeFileAbs(t, "c", "/a/b", "/a/b/c")
	testMakeFileAbs(t, "../c", "/a/b", "/a/c")
}

func testMakeFileAbs(t *testing.T, file, dir, expect string) {
	path, err := util.MakeFileAbs(file, dir)
	assert.NoError(t, err)

	if expect != "" {
		expect, _ = filepath.Abs(expect)
	}
	assert.Equal(t, expect, path)
}

var cert = `-----BEGIN CERTIFICATE-----
MIICYjCCAgmgAwIBAgIUB3CTDOU47sUC5K4kn/Caqnh114YwCgYIKoZIzj0EAwIw
fzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xHzAdBgNVBAoTFkludGVybmV0IFdpZGdldHMsIEluYy4xDDAK
BgNVBAsTA1dXVzEUMBIGA1UEAxMLZXhhbXBsZS5jb20wHhcNMTYxMDEyMTkzMTAw
WhcNMjExMDExMTkzMTAwWjB/MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZv
cm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEfMB0GA1UEChMWSW50ZXJuZXQg
V2lkZ2V0cywgSW5jLjEMMAoGA1UECxMDV1dXMRQwEgYDVQQDEwtleGFtcGxlLmNv
bTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKIH5b2JaSmqiQXHyqC+cmknICcF
i5AddVjsQizDV6uZ4v6s+PWiJyzfA/rTtMvYAPq/yeEHpBUB1j053mxnpMujYzBh
MA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQXZ0I9
qp6CP8TFHZ9bw5nRtZxIEDAfBgNVHSMEGDAWgBQXZ0I9qp6CP8TFHZ9bw5nRtZxI
EDAKBggqhkjOPQQDAgNHADBEAiAHp5Rbp9Em1G/UmKn8WsCbqDfWecVbZPQj3RK4
oG5kQQIgQAe4OOKYhJdh3f7URaKfGTf492/nmRmtK+ySKjpHSrU=
-----END CERTIFICATE-----
`

var errCert = `-----BEGIN ERROR CERTIFICATE-----
sLJGcSFzmXHJlmULJ9Ne8//jZlTKnS8dsZvbQu4i27c=
-----END ERROR CERTIFICATE-----`

func TestGetX509CertificateFromPEM(t *testing.T) {
	certBytes := []byte(cert)
	certificate, err := util.GetX509CertificateFromPEM(certBytes)
	require.NoError(t, err)
	require.NotNil(t, certificate)

	errCertBytes := []byte(errCert)
	certificate, err = util.GetX509CertificateFromPEM(errCertBytes)
	require.Error(t, err)
	require.Nil(t, certificate)
}

var rsaKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEA1fzWJrlEgbMFCOTIyplAsY9RB8MSQAhBzfZ55eg9qFiU5k1W
GQgvPdyJ2inFLfWZqKE4CyU4DMlAi3/yYoDsM+uXom8HZBmR9jtHAXBSbnPN5qrP
dzhn2P4E6us5DscIQgqqLbaVSjM5F2LBol2qXVVaSjK3x82DJx85ER/45SBC1IPI
FUsus43zcck+fZGxcCPYcUN35N1Hef8qo4gVR7or1Ry+I3wLHQI43mxC2QpWJ59E
Cq73tI+DATFByBDxKsie6EFXPCsfkSEXxVAF7RHfTHlIohLbMMRaGHzHRBrMadtS
Dsmb3tELHl8ZK+ZFBUaWM9uGDhucnvaKnNsakQIDAQABAoIBAQC3KVOkkbAx1Cnb
EvlLcSIO2b1iB3b3mBm7Ud3FDKS6FBhfiJLJmlfVe5ADTP2Z+T8tN9HguFrhluHI
hhvSdMe5KU8BmkeZRsnJGbQNZzcnk7gKWOp8Aavh8IwFCJIuM+69mKNRvZbLjEyx
17YmZEYO3aALIp5sR1ybf/44ykUg2IpgMI7hR+VVKSX3+PTovS737Pnoyv0LpsKb
z9ZOq1BTO1jP0i4sjuC0bOo1DQg4smXz83wdMBnDE8ikxRYEC+hVSjuyIAfGwZG8
lc16UP3YX7DYd87nhMZYI/ZFCwJCMP+btFnEvtgX25hF8uw2/fFUsXAF24bloJ/w
IuIDlpKBAoGBANfrqAA/+IFg55UDN56roZcao1DGFoTtih2MiKz3Hqp8mMZEY2ec
PQDrn6Qz9Zz4Lckjr8yiVXNAgPyfYTZHk6jVZJWAd73vRPnr83YeQbeqI5fDjBL8
GMbJmdqIibtZVj+WLUWjtzYnrGR+rilQH/8S26R9kFmRk8VQ1gsfd8njAoGBAP21
VMZwBDnSgsIrQF6uOQMqAIWGWjGDEDbpulCOLNErwKqWzqsWqpt7p6lk2DZH/K9O
AVsAK7QekHFjEHhnEgk9pfebEL7yUH68N6l3BGk8OXIRI1rj87ymWi+jzeuVP8u1
zC4JszJad4Z9LPvvJp5b/RqkR1GS/FoTjcuw04P7AoGBANCkhtK2/gsG+MClOzm3
342D0AxdXaVVZADpq6h3ospbW8U6kFOuRcR96uVg0BW+O4ABW/8BXlDgI8P4vpcU
0zpx+Z/9Y7fFXYGi3r9kvVwcrAgajWBK+iYc6O6iwXSn/w+yrkx8xq0t6Qey4dhJ
9KEmN9fa/YGPiptAYZSd88LBAoGBAJOu6zM732ndPVpTnPvARNWvrHANXhE2LskY
Uukzaak048kpUhJLdnJdj6JOXoFydAeDy8wyFD6cEA7A0MSVku0oIqU4cY4FNZAg
dfJCoqGzeekJSuBMkwP8fcD/hA2famxlXf5qjRJBkRQLZ5UbiApkl7fbatx0SEsS
2NZ6DxXjAoGBAKqvZzgyvMDYwuMnEtujPtsUAIuO0TOcBblBj/lKbXV3hZ6ofoR2
Q6BcipQGpC/nC919nicZAlTIX+hQRnXYT9aztD2dJNtxQQJ8jp65OkIxjL8SZwQ8
vxb0gUfiADp3eghIO5cwu9tbXdtx5XHAmVhPN7JdudVl+Ag6dtDmrkgi
-----END RSA PRIVATE KEY-----`

func TestGetRSAPrivateKey(t *testing.T) {
	_, err := util.GetRSAPrivateKey([]byte("hello"))
	assert.Error(t, err)

	_, err = util.GetRSAPrivateKey([]byte(rsaKey))
	assert.NoError(t, err)

	rsaK, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	encodedPK, err := x509.MarshalPKCS8PrivateKey(rsaK)
	require.NoError(t, err)

	pemEncodedPK := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedPK})
	_, err = util.GetRSAPrivateKey(pemEncodedPK)
	assert.NoError(t, err)

	_, err = util.GetRSAPrivateKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("hello")}))
	assert.Error(t, err)

	ecdsaK, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	encodedPK, err = x509.MarshalPKCS8PrivateKey(ecdsaK)
	require.NoError(t, err)

	pemEncodedPK = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedPK})
	_, err = util.GetRSAPrivateKey(pemEncodedPK)
	assert.Error(t, err)
}

var ecKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINs5XopZVBEWTsUCCF8mU4H14/UN1alo+j5BzBQZ0PKtoAoGCCqGSM49
AwEHoUQDQgAEogflvYlpKaqJBcfKoL5yaScgJwWLkB11WOxCLMNXq5ni/qz49aIn
LN8D+tO0y9gA+r/J4QekFQHWPTnebGekyw==
-----END EC PRIVATE KEY-----`

func TestGetECPrivateKey(t *testing.T) {
	_, err := util.GetECPrivateKey([]byte("hello"))
	assert.Error(t, err)

	_, err = util.GetECPrivateKey([]byte(ecKey))
	assert.NoError(t, err)

	ecdsaK, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	encodedPK, err := x509.MarshalPKCS8PrivateKey(ecdsaK)
	require.NoError(t, err)

	pemEncodedPK := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedPK})
	_, err = util.GetECPrivateKey(pemEncodedPK)
	assert.NoError(t, err)

	_, err = util.GetECPrivateKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("hello")}))
	assert.Error(t, err)

	rsaK, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	encodedPK, err = x509.MarshalPKCS8PrivateKey(rsaK)
	require.NoError(t, err)

	pemEncodedPK = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedPK})
	_, err = util.GetECPrivateKey(pemEncodedPK)
	assert.Error(t, err)
}

func TestGetEnrollmentIDFromPEM(t *testing.T) {
	certBytes := []byte(cert)
	_, err := util.GetEnrollmentIDFromPEM(certBytes)
	assert.NoError(t, err)
}

func TestRandomString(t *testing.T) {
	str := util.RandomString(10)
	assert.NotEmpty(t, str)
	assert.Len(t, str, 10)
}
