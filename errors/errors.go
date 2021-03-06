package errors

import (
	"fmt"
	"reflect"

	"github.com/pkg/errors"
)

// Error codes
var (
	// Unknown error code
	ErrUnknown = 0
	// HTTP method not allowed
	ErrMethodNotAllowed = 1
	// No authorization header was found in request
	ErrNoAuthHdr = 2
	// Failed reading the HTTP request body
	ErrReadingReqBody = 3
	// HTTP request body was empty but should not have been
	ErrEmptyReqBody = 4
	// HTTP request body was of the wrong format
	ErrBadReqBody = 5
	// Authorization failure
	ErrAuthenticationFailure = 20
	// No username and password were in the authorization header
	ErrNoUserPass = 21
	// Enrollment is currently disabled for the server
	ErrEnrollDisabled = 22
	// Invalid user name
	ErrInvalidUser = 23
	// Invalid password
	ErrInvalidPass = 24
	// Bad certificate signing request
	ErrBadCSR = 31
	// Error connecting to database
	ErrConnectingDB = 51
	// Error occured when making a Get request to database
	ErrDBGet = 63
	// Error occured while deleting user
	ErrDBDeleteUser = 65
	// Incorrect password limit reached
	ErrPasswordAttempts = 73
)

// CreateHTTPErr constructs a new HTTP error.
func CreateHTTPErr(scode, code int, format string, args ...interface{}) *HTTPErr {
	msg := fmt.Sprintf(format, args...)
	return &HTTPErr{
		scode: scode,
		lcode: code,
		lmsg:  msg,
		rcode: code,
		rmsg:  msg,
	}
}

// NewHTTPErr constructs a new HTTP error wrappered with pkg/errors error.
func NewHTTPErr(scode, code int, format string, args ...interface{}) error {
	return errors.Wrap(CreateHTTPErr(scode, code, format, args...), "")
}

// HTTPErr is an HTTP error.
type HTTPErr struct {
	scode int    // HTTP status code.
	lcode int    // local error code.
	lmsg  string // local error message.
	rcode int    // remote error code.
	rmsg  string // remote error message.
}

// Error returns the string representation
func (he *HTTPErr) Error() string {
	return he.String()
}

// GetStatusCode returns the HTTP status code
func (he *HTTPErr) GetStatusCode() int {
	return he.scode
}

// GetLocalCode returns the local error code
func (he *HTTPErr) GetLocalCode() int {
	return he.lcode
}

// GetLocalMsg returns the local error message
func (he *HTTPErr) GetLocalMsg() string {
	return he.lmsg
}

// GetRemoteCode returns the remote error code
func (he *HTTPErr) GetRemoteCode() int {
	return he.rcode
}

// GetRemoteMsg returns the remote error message
func (he *HTTPErr) GetRemoteMsg() string {
	return he.rmsg
}

// String returns a string representation of this augmented error
func (he *HTTPErr) String() string {
	if he.lcode == he.rcode && he.lmsg == he.rmsg {
		return fmt.Sprintf("scode: %d, code: %d, msg: %s", he.scode, he.lcode, he.lmsg)
	}
	return fmt.Sprintf("scode: %d, local code: %d, local msg: %s, remote code: %d, remote msg: %s",
		he.scode, he.lcode, he.lmsg, he.rcode, he.rmsg)
}

// Remote sets the remote code and message to something different from that of the local code and message
func (he *HTTPErr) Remote(code int, format string, args ...interface{}) *HTTPErr {
	he.rcode = code
	he.rmsg = fmt.Sprintf(format, args...)
	return he
}

// ServerErr contains error message with corresponding CA error code
type ServerErr struct {
	code int
	msg  string
}

// FatalErr is a server error that is will prevent the server/CA from continuing to operate
type FatalErr struct {
	ServerErr
}

// NewServerError constructs a server error
func NewServerError(code int, format string, args ...interface{}) *ServerErr {
	msg := fmt.Sprintf(format, args...)
	return &ServerErr{
		code: code,
		msg:  msg,
	}
}

// NewFatalError constructs a fatal error
func NewFatalError(code int, format string, args ...interface{}) *FatalErr {
	msg := fmt.Sprintf(format, args...)
	return &FatalErr{
		ServerErr{
			code: code,
			msg:  msg,
		},
	}
}

func (fe *FatalErr) Error() string {
	return fe.String()
}

func (fe *FatalErr) String() string {
	return fmt.Sprintf("Code: %d - %s", fe.code, fe.msg)
}

// IsFatalError return true if the error is of type 'FatalErr'
func IsFatalError(err error) bool {
	causeErr := errors.Cause(err)
	typ := reflect.TypeOf(causeErr)

	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}

	if typ == reflect.TypeOf(FatalErr{}) {
		return true
	}

	return false
}

// NewAuthenticationErr constructs an HTTP error specifically indicating an authentication failure.
func NewAuthenticationErr(code int, format string, args ...interface{}) error {
	he := CreateHTTPErr(401, code, format, args...)
	he.Remote(ErrAuthenticationFailure, "Authentication failure")
	return he
}
