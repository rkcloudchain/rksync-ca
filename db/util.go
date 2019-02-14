package db

import (
	"database/sql"

	"github.com/jmoiron/sqlx"
)

// CourierCADB is the interface with functions implemented by sqlx.DB
// object that are used by Courier CA server
type CourierCADB interface {
	IsInitialized() bool
	Select(dest interface{}, query string, args ...interface{}) error
	Exec(query string, args ...interface{}) (sql.Result, error)
	NamedExec(query string, arg interface{}) (sql.Result, error)
	Rebind(query string) string
	MustBegin() *sqlx.Tx
	BeginTx() CourierCATx
}

// CourierCATx is the interface with functions implemented by sqlx.Tx
// object that are used by Courier CA server
type CourierCATx interface {
	Queryx(query string, args ...interface{}) (*sqlx.Rows, error)
	Select(dest interface{}, query string, args ...interface{}) error
	Rebind(query string) string
	Exec(query string, args ...interface{}) (sql.Result, error)
	Commit() error
	Rollback() error
}

// DB is an adopter for sqlx.DB and implements
type DB struct {
	*sqlx.DB
	IsDBInitialized bool
}

// BeginTx implements BeginTx method of CourierCADB interface
func (db *DB) BeginTx() CourierCATx {
	return db.MustBegin()
}

// IsInitialized returns true if db is initialized, else false
func (db *DB) IsInitialized() bool {
	return db.IsDBInitialized
}
