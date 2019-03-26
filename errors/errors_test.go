package errors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFatalError(t *testing.T) {
	err := NewFatalError(25, "fatal error: %s", "server")
	assert.Equal(t, 25, err.code)
	assert.Equal(t, "fatal error: server", err.msg)

	assert.Equal(t, "Code: 25 - fatal error: server", err.Error())
}

func TestIsFatalError(t *testing.T) {
	ferr := NewFatalError(25, "fatal error: %s", "server")
	assert.True(t, IsFatalError(ferr))

	err := NewAuthenticationErr(11, "auth error: %s", "server")
	assert.False(t, IsFatalError(err))
}
