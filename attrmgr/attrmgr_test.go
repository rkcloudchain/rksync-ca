package attrmgr_test

import (
	"crypto/x509"
	"testing"

	"github.com/rkcloudchain/rksync-ca/api"
	"github.com/rkcloudchain/rksync-ca/attrmgr"
	"github.com/stretchr/testify/assert"
)

func TestAttrs(t *testing.T) {
	mgr := attrmgr.New()
	cert := &x509.Certificate{}
	at, err := mgr.GetAttributesFromCert(cert)
	assert.NoError(t, err)
	assert.True(t, len(at.Names()) == 0)

	attrs := []attrmgr.Attribute{
		&api.Attribute{Name: "attr1", Value: "val1"},
		&api.Attribute{Name: "attr2", Value: "val2"},
		&api.Attribute{Name: "attr3", Value: "val3"},
		&api.Attribute{Name: "boolAttr", Value: "true"},
	}
	reqs := []attrmgr.AttributeRequest{
		&api.AttributeRequest{Name: "attr1", Optional: true},
		&api.AttributeRequest{Name: "attr2", Optional: false},
		&api.AttributeRequest{Name: "boolAttr", Optional: false},
		&api.AttributeRequest{Name: "noattr1", Optional: true},
	}

	err = mgr.ProcessAttributeRequestsForCert(reqs, attrs, cert)
	assert.NoError(t, err)

	at, err = mgr.GetAttributesFromCert(cert)
	assert.NoError(t, err)
	assert.True(t, len(at.Names()) == 3)
	assert.NoError(t, at.True("boolAttr"))
	checkAttr(t, "attr1", "val1", at)
	checkAttr(t, "attr2", "val2", at)
	checkAttr(t, "attr3", "", at)
	checkAttr(t, "noattr1", "", at)
}

func checkAttr(t *testing.T, name, val string, attrs *attrmgr.Attributes) {
	v, ok, err := attrs.Value(name)
	assert.NoError(t, err)
	if val == "" {
		assert.False(t, ok)
		assert.False(t, attrs.Contains(name))
	} else {
		assert.True(t, ok)
		assert.True(t, attrs.Contains(name))
		assert.Equal(t, val, v)
	}
}
