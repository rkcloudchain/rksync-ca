package db

import (
	"encoding/json"

	"github.com/cloudflare/cfssl/log"
	"github.com/pkg/errors"
	"github.com/rkcloudchain/rksync-ca/api"
	"github.com/rkcloudchain/rksync-ca/api/registry"
	"golang.org/x/crypto/bcrypt"
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

// GetFailedLoginAttempts returns the number of times the user has entered an incorrect password
func (u *User) GetFailedLoginAttempts() int {
	return u.IncorrectPasswordAttempts
}

// IncrementIncorrectPasswordAttempts updates the incorrect password count of user
func (u *User) IncrementIncorrectPasswordAttempts() error {
	log.Debugf("Incorrect password entered by user '%s'", u.GetName())
	query := "UPDATE users SET incorrect_password_attempts = incorrect_password_attempts + 1 where (id = ?)"
	id := u.GetName()
	res, err := u.db.Exec(u.db.Rebind(query), id)
	if err != nil {
		return err
	}
	numRowsAffected, err := res.RowsAffected()
	if err != nil {
		return errors.Wrap(err, "Failed to get number of rows affected")
	}

	if numRowsAffected == 0 {
		return errors.Errorf("No rows affected when updating the state of identity %s", id)
	}
	if numRowsAffected != 1 {
		return errors.Errorf("%d rows were affected when updating the state of identity %s", numRowsAffected, id)
	}

	return nil
}

// Login the user with a password
func (u *User) Login(pass string, caMaxEnrollment int) error {
	log.Debugf("DB: Login user %s with max enrollment of %d and state of %d", u.Name, u.MaxEnrollments, u.State)

	err := bcrypt.CompareHashAndPassword(u.pass, []byte(pass))
	if err != nil {
		err2 := u.IncrementIncorrectPasswordAttempts()
		if err2 != nil {
			return errors.Wrap(err, "Failed to mark incorrect password attempt")
		}
		return errors.Wrap(err, "Password mismatch")
	}

	if u.MaxEnrollments == 0 {
		return errors.Errorf("Zero is an invalid value for maximum enrollment on identity '%s'", u.Name)
	}

	if u.State == -1 {
		return errors.Errorf("User %s is revoked; access denied", u.Name)
	}

	if caMaxEnrollment != -1 && (u.MaxEnrollments > caMaxEnrollment || u.MaxEnrollments == -1) {
		log.Debugf("Max enrollment value (%d) of identity is greater than allowed by CA, using CA max enrollment value of %d", u.MaxEnrollments, caMaxEnrollment)
		u.MaxEnrollments = caMaxEnrollment
	}

	if u.MaxEnrollments != -1 && u.State >= u.MaxEnrollments {
		return errors.Errorf("The identity %s has already enrolled %d times, it has reached its maximum enrollment allowance", u.Name, u.MaxEnrollments)
	}

	log.Debugf("DB: identity %s successfully logged in", u.Name)

	return u.resetIncorrectLoginAttempts()
}

func (u *User) resetIncorrectLoginAttempts() error {
	var passAttempts int
	err := u.db.Get(&passAttempts, u.db.Rebind("Select incorrect_password_attempts FROM users WHERE (id = ?)"), u.GetName())
	if err != nil {
		return errors.Wrapf(err, "Failed to get incorrect password attempt for %s", u.Name)
	}

	if passAttempts == 0 {
		return nil
	}

	resetSQL := "UPDATE users SET incorrect_password_attempts = 0 WHERE (id = ?)"
	res, err := u.db.Exec(u.db.Rebind(resetSQL), u.GetName())
	if err != nil {
		return errors.Wrapf(err, "Failed to update incorrect password attempt count to 0 for %s", u.Name)
	}

	numRowsAffected, err := res.RowsAffected()
	if err != nil {
		return errors.Wrap(err, "db.RowsAffected failed")
	}

	if numRowsAffected == 0 {
		return errors.Errorf("No rows were affected when updating the state of identity %s", u.Name)
	}
	if numRowsAffected != 1 {
		return errors.Errorf("%d rows were affected when updating the state of identity %s", numRowsAffected, u.Name)
	}

	return nil
}

// LoginComplete completes the login process by incrementing the state of the user
func (u *User) LoginComplete() error {
	var stateUpdateSQL string
	var args []interface{}
	var err error

	state := u.State + 1
	args = append(args, u.Name)
	if u.MaxEnrollments == -1 {
		stateUpdateSQL = "UPDATE users SET state = state + 1 WHERE (id = ?)"
	} else {
		stateUpdateSQL = "UPDATE users SET state = state + 1 WHERE (id = ? AND state < ?)"
		args = append(args, u.MaxEnrollments)
	}
	res, err := u.db.Exec(u.db.Rebind(stateUpdateSQL), args...)
	if err != nil {
		return errors.Wrapf(err, "Failed to update state of identity %s to %d", u.Name, state)
	}

	numRowsAffected, err := res.RowsAffected()
	if err != nil {
		return errors.Wrap(err, "db.RowsAffected failed")
	}

	if numRowsAffected == 0 {
		return errors.Errorf("No rows were affected when updating the state of identity %s", u.Name)
	}
	if numRowsAffected != 1 {
		return errors.Errorf("%d rows were affected when updating the state of identity %s", numRowsAffected, u.Name)
	}

	log.Debugf("Successfully incremented state for identity %s to %d", u.Name, state)
	return nil
}
