package util

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/pkg/errors"
	"github.com/rkcloudchain/cccsp"
	"github.com/rkcloudchain/cccsp/hash"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var (
	rnd = rand.NewSource(time.Now().UnixNano())
)

const (
	letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

// FileExists checks to see if a file exists.
func FileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// MakeFileNamesAbsolute makes all file names in the list absolute, relative to home
func MakeFileNamesAbsolute(files []*string, home string) error {
	for _, filePtr := range files {
		abs, err := MakeFileAbs(*filePtr, home)
		if err != nil {
			return err
		}
		*filePtr = abs
	}
	return nil
}

// MakeFileAbs makes 'file' absolute relative to 'dir' if not already absolute
func MakeFileAbs(file, dir string) (string, error) {
	if file == "" {
		return "", nil
	}
	if filepath.IsAbs(file) {
		return file, nil
	}
	path, err := filepath.Abs(filepath.Join(dir, file))
	if err != nil {
		return "", errors.Wrapf(err, "Failed making '%s' absolute based on '%s'", file, dir)
	}
	return path, nil
}

// GetX509CertificateFromPEM get on x509 certificate from bytes in PEM format
func GetX509CertificateFromPEM(cert []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(cert)
	if block == nil {
		return nil, errors.New("Failed to PEM decode certificate")
	}
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "Error parsing certificate")
	}
	return x509Cert, nil
}

// GetRSAPrivateKey get *rsa.PrivateKey from key pem
func GetRSAPrivateKey(raw []byte) (*rsa.PrivateKey, error) {
	decoded, _ := pem.Decode(raw)
	if decoded == nil {
		return nil, errors.New("Failed to decode the PEM-encoded RSA key")
	}
	RSAPrivKey, err := x509.ParsePKCS1PrivateKey(decoded.Bytes)
	if err == nil {
		return RSAPrivKey, nil
	}
	key, err2 := x509.ParsePKCS8PrivateKey(decoded.Bytes)
	if err2 == nil {
		switch key.(type) {
		case *ecdsa.PrivateKey:
			return nil, errors.New("Expecting RSA private key but found EC private key")
		case *rsa.PrivateKey:
			return key.(*rsa.PrivateKey), nil
		default:
			return nil, errors.New("Invalid private key type in PKCS#8 wrapping")
		}
	}
	return nil, errors.Wrap(err, "Failed parsing RSA private key")
}

// GetECPrivateKey get *ecdsa.PrivateKey from key pem
func GetECPrivateKey(raw []byte) (*ecdsa.PrivateKey, error) {
	decoded, _ := pem.Decode(raw)
	if decoded == nil {
		return nil, errors.New("Failed to decode the PEM-encoded ECDSA key")
	}
	ECPrivKey, err := x509.ParseECPrivateKey(decoded.Bytes)
	if err == nil {
		return ECPrivKey, nil
	}
	key, err2 := x509.ParsePKCS8PrivateKey(decoded.Bytes)
	if err2 == nil {
		switch key.(type) {
		case *ecdsa.PrivateKey:
			return key.(*ecdsa.PrivateKey), nil
		case *rsa.PrivateKey:
			return nil, errors.New("Expecting EC private key but found RSA private key")
		default:
			return nil, errors.New("Invalid private key type in PKCS#8 wrapping")
		}
	}
	return nil, errors.Wrap(err, "Failed parsing EC private key")
}

// GetEnrollmentIDFromPEM returns the EnrollmentID from a PEM buffer
func GetEnrollmentIDFromPEM(cert []byte) (string, error) {
	x509Cert, err := GetX509CertificateFromPEM(cert)
	if err != nil {
		return "", err
	}

	return GetEnrollmentIDFromX509Certificate(x509Cert), nil
}

// GetEnrollmentIDFromX509Certificate returns the EnrollmentID from the x509 certificate
func GetEnrollmentIDFromX509Certificate(cert *x509.Certificate) string {
	return cert.Subject.CommonName
}

// URLRegex is the regular expression to check if a value is an URL
var URLRegex = regexp.MustCompile("(http)s*://(\\S+):(\\S+)@")

// GetMaskedURL returns masked URL. It masks username and password from the URL if present
func GetMaskedURL(url string) string {
	matches := URLRegex.FindStringSubmatch(url)
	if len(matches) == 4 {
		matchIdxs := URLRegex.FindStringSubmatchIndex(url)
		matchStr := url[matchIdxs[0]:matchIdxs[1]]
		for idx := 2; idx < len(matches); idx++ {
			if matches[idx] != "" {
				matchStr = strings.Replace(matchStr, matches[idx], "****", 1)
			}
		}
		url = url[:matchIdxs[0]] + matchStr + url[matchIdxs[1]:len(url)]
	}
	return url
}

// Marshal to bytes
func Marshal(from interface{}, what string) ([]byte, error) {
	buf, err := json.Marshal(from)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to marshal %s", what)
	}
	return buf, nil
}

// Unmarshal from bytes
func Unmarshal(from []byte, to interface{}, what string) error {
	err := json.Unmarshal(from, to)
	if err != nil {
		return errors.Wrapf(err, "Failed to unmarshal %s", what)
	}
	return nil
}

// WriteFile writes a file
func WriteFile(file string, buf []byte, perm os.FileMode) error {
	dir := filepath.Dir(file)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			return errors.Wrapf(err, "Failed to create directory '%s' for file '%s'", dir, file)
		}
	}
	return ioutil.WriteFile(file, buf, perm)
}

// GetSerialAsHex returns the serial number from certificate as hex format
func GetSerialAsHex(serial *big.Int) string {
	hex := fmt.Sprintf("%x", serial)
	return hex
}

// CreateToken creates a JWT-like token.
func CreateToken(csp cccsp.CCCSP, cert []byte, key cccsp.Key, method, uri string, body []byte) (string, error) {
	x509Cert, err := GetX509CertificateFromPEM(cert)
	if err != nil {
		return "", err
	}
	publicKey := x509Cert.PublicKey

	var token string
	switch publicKey.(type) {
	case *ecdsa.PublicKey:
		token, err = GenECDSAToken(csp, cert, key, method, uri, body)
		if err != nil {
			return "", err
		}
	}

	return token, nil
}

// GenECDSAToken signs the http body and cert with ECDSA using EC private key
func GenECDSAToken(csp cccsp.CCCSP, cert []byte, key cccsp.Key, method, uri string, body []byte) (string, error) {
	b64body := base64.StdEncoding.EncodeToString(body)
	b64cert := base64.StdEncoding.EncodeToString(cert)
	b64uri := base64.StdEncoding.EncodeToString([]byte(uri))
	payload := method + "." + b64uri + "." + b64body + "." + b64cert

	return genECDSAToken(csp, key, b64cert, payload)
}

func genECDSAToken(csp cccsp.CCCSP, key cccsp.Key, b64cert, payload string) (string, error) {
	digest, digestError := csp.Hash([]byte(payload), string(hash.SHA3256))
	if digestError != nil {
		return "", errors.WithMessage(digestError, fmt.Sprintf("Hash failed on '%s'", payload))
	}

	ecSignature, err := csp.Sign(key, digest, nil)
	if err != nil {
		return "", errors.WithMessage(err, "CCCSP signature generation failure")
	}
	if len(ecSignature) == 0 {
		return "", errors.New("CCCSP signature creation failed. Signature must be different than nil")
	}

	b64sig := base64.StdEncoding.EncodeToString(ecSignature)
	token := b64cert + "." + b64sig
	return token, nil
}

// NormalizeStringSlice checks for seperators
func NormalizeStringSlice(slice []string) []string {
	var normalizeSlice []string

	if len(slice) > 0 {
		for _, item := range slice {
			if strings.HasPrefix(item, "[") && strings.HasSuffix(item, "]") {
				item = item[1 : len(item)-1]
			}

			if strings.Contains(item, ",") {
				normalizeSlice = append(normalizeSlice, strings.Split(item, ",")...)
			} else {
				normalizeSlice = append(normalizeSlice, item)
			}
		}
	}
	return normalizeSlice
}

// Read reads from Reader into a byte array
func Read(r io.Reader, data []byte) ([]byte, error) {
	j := 0
	for {
		n, err := r.Read(data[j:])
		j = j + n
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, errors.Wrap(err, "Read failure")
		}

		if (n == 0 && j == len(data)) || j > len(data) {
			return nil, errors.New("Size of requested data is too large")
		}
	}

	return data[:j], nil
}

// Fatal logs fatal message and exists
func Fatal(format string, v ...interface{}) {
	log.Fatalf(format, v...)
	os.Exit(1)
}

// RandomString returns a random string
func RandomString(n int) string {
	b := make([]byte, n)

	for i, cache, remain := n-1, rnd.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = rnd.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

// FlagString sets up a flag for a string, binding it to its name
func FlagString(v *viper.Viper, flags *pflag.FlagSet, name, short string, def string, desc string) {
	flags.StringP(name, short, def, desc)
	bindFlag(v, flags, name)
}

// common binding function
func bindFlag(v *viper.Viper, flags *pflag.FlagSet, name string) {
	flag := flags.Lookup(name)
	if flag == nil {
		panic(errors.Errorf("failed to lookup '%s'", name))
	}
	v.BindPFlag(name, flag)
}
