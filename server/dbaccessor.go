package server

import (
	"encoding/json"

	"github.com/cloudflare/cfssl/log"
	"github.com/jmoiron/sqlx"
	"github.com/kisielk/sqlstruct"
	"github.com/pkg/errors"
	"github.com/rkcloudchain/courier-ca/api/registry"
	dbutil "github.com/rkcloudchain/courier-ca/db"
	caerrors "github.com/rkcloudchain/courier-ca/errors"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ocsp"
)

func init() {
	sqlstruct.TagName = "db"
}

const (
	insertUser = `
INSERT INTO users (id, token, attributes, state, max_enrollments, incorrect_password_attempts)
VALUES (:id, :token, :attributes, :state, :max_enrollments, :incorrect_password_attempts);`

	deleteUser = `
DELETE FROM users
	WHERE (id = ?);`

	updateUser = `
UPDATE users
SET token = :token, attributes = :attributes, state = :state, max_enrollments = :max_enrollments, incorrect_password_attempts = :incorrect_password_attempts
	WHERE (id = :id);`

	getUser = `
SELECT * FROM users
	WHERE (id = ?)`
)

// Accessor implements db.Accessor interface
type Accessor struct {
	db *dbutil.DB
}

// NewDBAccessor si a constructor for the database API
func NewDBAccessor(db *dbutil.DB) *Accessor {
	return &Accessor{db}
}

func (d *Accessor) checkDB() error {
	if d.db == nil {
		return errors.New("Failed to correctly setup database connection")
	}
	return nil
}

// SetDB changes the underlying sql.DB object Accessor is manipulating.
func (d *Accessor) SetDB(db *dbutil.DB) {
	d.db = db
}

// InsertUser inserts user into database
func (d *Accessor) InsertUser(user *registry.UserInfo) error {
	if user == nil {
		return errors.New("User is not defined")
	}
	log.Debugf("DB: Add identity %s", user.Name)

	err := d.checkDB()
	if err != nil {
		return err
	}

	attrBytes, err := json.Marshal(user.Attributes)
	if err != nil {
		return err
	}

	pwd := []byte(user.Pass)
	pwd, err = bcrypt.GenerateFromPassword(pwd, bcrypt.DefaultCost)
	if err != nil {
		return errors.Wrap(err, "Failed to hash password")
	}

	res, err := d.db.NamedExec(insertUser, &dbutil.UserRecord{
		Name:                      user.Name,
		Pass:                      pwd,
		Attributes:                string(attrBytes),
		State:                     user.State,
		MaxEnrollment:             user.MaxEnrollments,
		IncorrectPasswordAttempts: 0,
	})

	if err != nil {
		return errors.Wrapf(err, "Error adding identity '%s' to the database", user.Name)
	}

	numRowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if numRowsAffected == 0 {
		return errors.Errorf("Failed to add identity %s to the database", user.Name)
	}
	if numRowsAffected != 1 {
		return errors.Errorf("Expected to add one record to the database, but %d records were added", numRowsAffected)
	}

	log.Debugf("Successfully added identity %s to the database", user.Name)
	return nil
}

// DeleteUser deletes user from database
func (d *Accessor) DeleteUser(id string) (registry.User, error) {
	log.Debugf("DB: Delete identity %s", id)

	result, err := d.doTransaction(d.deleteUserTx, id, ocsp.CessationOfOperation)
	if err != nil {
		return nil, err
	}

	userRec := result.(*dbutil.UserRecord)
	user := dbutil.NewDBUser(userRec, d.db)
	return user, nil
}

func (d *Accessor) deleteUserTx(tx *sqlx.Tx, args ...interface{}) (interface{}, error) {
	id := args[0].(string)
	reason := args[1].(int)

	var userRec dbutil.UserRecord
	err := tx.Get(&userRec, tx.Rebind(getUser), id)
	if err != nil {
		return nil, getError(err, "User")
	}

	_, err = tx.Exec(tx.Rebind(deleteUser), id)
	if err != nil {
		return nil, caerrors.NewHTTPErr(500, caerrors.ErrDBDeleteUser, "Error deleting identity '%s': %s", id, err)
	}

	record := &CertRecord{
		ID: id,
	}
	record.Reason = reason

	_, err = tx.NamedExec(tx.Rebind(updateRevokeSQL), record)
	if err != nil {
		return nil, caerrors.NewHTTPErr(500, caerrors.ErrDBDeleteUser, "Error encountered while revoking certificates for identity '%s' that is being deleted: %s", id, err)
	}

	return &userRec, nil
}

// UpdateUser updates user in database
func (d *Accessor) UpdateUser(user *registry.UserInfo, updatePass bool) error {
	if user == nil {
		return errors.New("User is not defined")
	}

	log.Debugf("DB: Update identity %s", user.Name)
	err := d.checkDB()
	if err != nil {
		return err
	}

	attributes, err := json.Marshal(user.Attributes)
	if err != nil {
		return errors.Wrap(err, "Failed to marshal user attributes")
	}

	pwd := []byte(user.Pass)
	if updatePass {
		pwd, err = bcrypt.GenerateFromPassword(pwd, bcrypt.DefaultCost)
		if err != nil {
			return errors.Wrap(err, "Failed to hash password")
		}
	}

	res, err := d.db.NamedExec(updateUser, &dbutil.UserRecord{
		Name:                      user.Name,
		Pass:                      pwd,
		Attributes:                string(attributes),
		State:                     user.State,
		MaxEnrollment:             user.MaxEnrollments,
		IncorrectPasswordAttempts: user.IncorrectPasswordAttempts,
	})

	if err != nil {
		return errors.Wrap(err, "Failed to update identity record")
	}

	numRowsAffected, err := res.RowsAffected()

	if numRowsAffected == 0 {
		return errors.New("No identity records were updated")
	}

	if numRowsAffected != 1 {
		return errors.Errorf("Expected one identity record to be updated, but %d records were updated", numRowsAffected)
	}

	return err
}

// GetUser gets user from database
func (d *Accessor) GetUser(id string, attrs []string) (registry.User, error) {
	log.Debugf("DB: Getting identity %s", id)

	err := d.checkDB()
	if err != nil {
		return nil, err
	}

	var userRec dbutil.UserRecord
	err = d.db.Get(&userRec, d.db.Rebind(getUser), id)
	if err != nil {
		return nil, getError(err, "User")
	}

	return dbutil.NewDBUser(&userRec, d.db), nil
}

func (d *Accessor) doTransaction(doit func(tx *sqlx.Tx, args ...interface{}) (interface{}, error), args ...interface{}) (interface{}, error) {
	err := d.checkDB()
	if err != nil {
		return nil, err
	}

	tx := d.db.MustBegin()
	result, err := doit(tx, args...)
	if err != nil {
		err2 := tx.Rollback()
		if err2 != nil {
			log.Errorf("Error encountered while rolling back transaction: %s", err2)
			return nil, err
		}
		return nil, err
	}

	err = tx.Commit()
	if err != nil {
		return nil, errors.Wrap(err, "Error encountered while committing transaction")
	}

	return result, nil
}
