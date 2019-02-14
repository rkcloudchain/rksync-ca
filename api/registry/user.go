package registry

import "github.com/rkcloudchain/courier-ca/api"

// UserInfo contains information about a user
type UserInfo struct {
	Name                      string
	Pass                      string
	Attributes                []api.Attribute
	State                     int
	MaxEnrollments            int
	IncorrectPasswordAttempts int
}

// User is the user interface used by courier-ca server
type User interface {
	GetName() string
	GetMaxEnrollments() int
	GetAttribute(name string) (*api.Attribute, error)
	GetAttributes(attrNames []string) ([]api.Attribute, error)
	GetFailedLoginAttempts() int
	IncrementIncorrectPasswordAttempts() error
	Login(password string, caMaxEnrollment int) error
	LoginComplete() error
}

// UserRegistry is the API for retreiving users
type UserRegistry interface {
	GetUser(id string, attrs []string) (User, error)
	InsertUser(user *UserInfo) error
	UpdateUser(user *UserInfo, updatePass bool) error
	DeleteUser(id string) (User, error)
}
