package util_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/cloudflare/cfssl/csr"
	"github.com/rkcloudchain/cccsp"
	"github.com/rkcloudchain/cccsp/provider"
	"github.com/rkcloudchain/rksync-ca/util"
	"github.com/stretchr/testify/require"
)

var tempDir string
var csp cccsp.CCCSP

func TestMain(m *testing.M) {
	var err error
	tempDir, err = ioutil.TempDir("", "cccsp")
	if err != nil {
		fmt.Printf("Failed to create temporary directory: %s\n\n", err)
		os.Exit(-1)
	}
	defer os.RemoveAll(tempDir)

	fks, err := provider.NewFileKEyStore(tempDir)
	if err != nil {
		fmt.Printf("Failed to create file keystore: %s\n\n", err)
		os.Exit(-1)
	}
	csp = provider.New(fks)

	ret := m.Run()
	os.Exit(ret)
}

func TestGetSignerFromCertFile(t *testing.T) {
	t.Run("ec", func(t *testing.T) {
		testGetSignerFromCertFile(t, "../testdata/ec-key.pem", "../testdata/ec.pem", 0)
	})

	t.Run("nokey", func(t *testing.T) {
		testGetSignerFromCertFile(t, "doesnotexist.pem", "../testdata/ec.pem", 1)
	})

	t.Run("nocert", func(t *testing.T) {
		testGetSignerFromCertFile(t, "../testdata/ec-key.pem", "doesnotexist.pem", 2)
	})

	t.Run("cert4key", func(t *testing.T) {
		testGetSignerFromCertFile(t, "../testdata/ec.pem", "../testdata/ec.pem", 1)
	})

	t.Run("rsa", func(t *testing.T) {
		testGetSignerFromCertFile(t, "../testdata/rsa-key.pem", "../testdata/rsa.pem", 1)
	})

	t.Run("wrongcert", func(t *testing.T) {
		testGetSignerFromCertFile(t, "../testdata/ec-key.pem", "../testdata/rsa.pem", 2)
	})
}

func testGetSignerFromCertFile(t *testing.T, keyFile, certFile string, mustFail int) {
	key, err := util.ImportCCCSPKeyFromPEM(keyFile, csp, false)
	if mustFail == 1 {
		require.Error(t, err)
		return
	}

	require.NoError(t, err)
	require.NotNil(t, key)

	key, signer, cert, err := util.GetSignerFromCertFile(certFile, csp)
	if mustFail == 2 {
		require.Error(t, err)
	} else {
		require.NoError(t, err)
		require.NotNil(t, key)
		require.NotNil(t, signer)
		require.NotNil(t, cert)
	}

	cer, err := util.LoadX509KeyPair(certFile, keyFile, csp)
	if mustFail == 2 {
		require.Error(t, err)
	} else {
		require.NoError(t, err)
		require.NotNil(t, cer.Certificate[0])
	}
}

func TestKeyGenerate(t *testing.T) {
	t.Run("256", func(t *testing.T) { testKeyGenerate(t, csr.NewBasicKeyRequest(), false) })
	t.Run("384", func(t *testing.T) { testKeyGenerate(t, &csr.BasicKeyRequest{A: "ecdsa", S: 384}, false) })
	t.Run("521", func(t *testing.T) { testKeyGenerate(t, &csr.BasicKeyRequest{A: "ecdsa", S: 521}, false) })
	t.Run("521", func(t *testing.T) { testKeyGenerate(t, &csr.BasicKeyRequest{A: "ecdsa", S: 224}, true) })
	t.Run("512", func(t *testing.T) { testKeyGenerate(t, &csr.BasicKeyRequest{A: "rsa", S: 512}, true) })
	t.Run("1024", func(t *testing.T) { testKeyGenerate(t, &csr.BasicKeyRequest{A: "rsa", S: 1024}, true) })
	t.Run("2048", func(t *testing.T) { testKeyGenerate(t, &csr.BasicKeyRequest{A: "rsa", S: 2048}, false) })
	t.Run("3072", func(t *testing.T) { testKeyGenerate(t, &csr.BasicKeyRequest{A: "rsa", S: 3072}, false) })
	t.Run("4096", func(t *testing.T) { testKeyGenerate(t, &csr.BasicKeyRequest{A: "rsa", S: 4096}, false) })
	t.Run("4097", func(t *testing.T) { testKeyGenerate(t, &csr.BasicKeyRequest{A: "rsa", S: 4097}, true) })
	t.Run("10000", func(t *testing.T) { testKeyGenerate(t, &csr.BasicKeyRequest{A: "rsa", S: 10000}, true) })
	t.Run("empty", func(t *testing.T) { testKeyGenerate(t, &csr.BasicKeyRequest{}, true) })
	t.Run("nil", func(t *testing.T) { testKeyGenerate(t, nil, false) })
}

func testKeyGenerate(t *testing.T, kr csr.KeyRequest, mustFail bool) {
	req := csr.CertificateRequest{
		KeyRequest: kr,
	}

	key, signer, err := util.CCCSPKeyRequestGenerate(&req, csp)
	if mustFail {
		require.Error(t, err)
	} else {
		require.NoError(t, err)
		require.NotNil(t, key)
		require.NotNil(t, signer)
	}
}
