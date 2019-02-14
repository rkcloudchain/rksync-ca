package db

import (
	"encoding/json"

	"github.com/pkg/errors"
	"github.com/rkcloudchain/courier-ca/api"
	"github.com/rkcloudchain/courier-ca/api/registry"
)

// UserRecord defines the properties of user
type UserRecord struct {
	Name                      string `db:"id"`
	Pass                      []byte `db:"token"`
	Attributes                string `db:"attributes"`
	State                     int    `db:"state"`
	MaxEnrollment             int    `db:"max_enrollments"`
	IncorrectPasswordAttempts int    `db:"incorrect_password_attempts"`
}

// User is the database representation of a user
type User struct {
	registry.UserInfo
	pass  []byte
	attrs map[string]api.Attribute
	db    *DB
}

// NewDBUser creates a User object from the DB user record
func NewDBUser(userRec *UserRecord, db *DB) *User {
	var user = new(User)
	user.Name = userRec.Name
	user.pass = userRec.Pass
	user.State = userRec.State
	user.MaxEnrollments = userRec.MaxEnrollment
	user.IncorrectPasswordAttempts = userRec.IncorrectPasswordAttempts

	var attrs []api.Attribute
	json.Unmarshal([]byte(userRec.Attributes), &attrs)
	user.Attributes = attrs

	user.attrs = make(map[string]api.Attribute)
	for _, attr := range attrs {
		user.attrs[attr.Name] = api.Attribute{
			Name:  attr.Name,
			Value: attr.Value,
			ECert: attr.ECert,
		}
	}

	user.db = db
	return user
}

// GetName returns the enrollment ID of the user
func (u *User) GetName() string {
	return u.Name
}

// GetMaxEnrollments returns the max enrollments of the user
func (u *User) GetMaxEnrollments() int {
	return u.MaxEnrollments
}

// GetAttribute returns the value for an attribute name
func (u *User) GetAttribute(name string) (*api.Attribute, error) {
	value, hasAttr := u.attrs[name]
	if !hasAttr {
		return nil, errors.Errorf("User does not have attribute '%s'", name)
	}
	return &value, nil
}

// GetAttributes returns the requested attributes.
func (u *User) GetAttributes(attrNames []string) ([]api.Attribute, error) {
	var attrs []api.Attribute
	if attrNames == nil {
		for _, value := range u.attrs {
			attrs = append(attrs, value)
		}
		return attrs, nil
	}

	for _, name := range attrNames {
		value, hasAttr := u.attrs[name]
		if !hasAttr {
			return nil, errors.Errorf("User does not have attribute '%s'", name)
		}
		attrs = append(attrs, value)
	}
	return attrs, nil
}
