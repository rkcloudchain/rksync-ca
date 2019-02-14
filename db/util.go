package db

import (
	"database/sql"
	"fmt"
	"regexp"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
)

var (
	dbURLRegex = regexp.MustCompile("(Datasource:\\s*)?(\\S+):(\\S+)@|(Datasource:.*\\s)?(user=\\S+).*\\s(password=\\S+)|(Datasource:.*\\s)?(password=\\S+).*\\s(user=\\S+)")
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

// NewUserRegistryMySQL opens a connection to a MySQL database
func NewUserRegistryMySQL(datasource string) (*DB, error) {
	log.Debugf("Using MySQL database, connecting to database...")

	dbName := getDBName(datasource)
	log.Debugf("Database Name: %s", dbName)

	re := regexp.MustCompile(`\/([0-9,a-z,A-Z$_]+)`)
	connStr := re.ReplaceAllString(datasource, "/")

	log.Debugf("Connecting to MySQL server, using connecting string: %s", MakeDBCred(connStr))
	db, err := sqlx.Open("mysql", connStr)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to open MySQL database")
	}

	err = db.Ping()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to connect to MySQL database")
	}

	err = createMySQLDatabase(dbName, db)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create MySQL database")
	}

	log.Debugf("Connecting to database '%s', using connection string: '%s'", dbName, MakeDBCred(datasource))
	db, err = sqlx.Open("mysql", datasource)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to open database (%s) in MySQL server", dbName)
	}

	err = createMySQLTables(dbName, db)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create MySQL tables")
	}

	return &DB{db, false}, nil
}

func createMySQLDatabase(dbName string, db *sqlx.DB) error {
	log.Debugf("Creating MySQL Database (%s) if it does not exists...", dbName)

	_, err := db.Exec("CREATE DATABASE IF NOT EXISTS " + dbName)
	if err != nil {
		return errors.Wrap(err, "Failed to execute create database query")
	}

	return nil
}

func createMySQLTables(dbName string, db *sqlx.DB) error {
	return nil
}

// NewUserRegistryPostgres opens a connection to a postgres database
func NewUserRegistryPostgres(datasource string) (*DB, error) {
	log.Debugf("Using postgres database, connection to database...")

	dbName := getDBName(datasource)
	log.Debugf("Database Name: %s", dbName)

	if strings.Contains(dbName, "-") || strings.HasSuffix(dbName, ".db") {
		return nil, errors.Errorf("Database name '%s' cannot contain any '-' or end with '.db'", dbName)
	}

	dbNames := []string{dbName, "postgres", "template1"}
	var db *sqlx.DB
	var pingErr, err error

	for _, dbName := range dbNames {
		connStr := getConnStr(datasource, dbName)
		log.Debugf("Connecting to PostgreSQL server, using connection string: %s", MakeDBCred(connStr))

		db, err := sqlx.Open("postgres", connStr)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to open Postgres database")
		}

		pingErr = db.Ping()
		if pingErr == nil {
			break
		}
		log.Warningf("Failed to connect to database '%s'", dbName)
	}

	if pingErr != nil {
		return nil, errors.Errorf("Failed to connect to Postgres database. Postgres requires connecting to a specific database, the following databases were tried: %s. Please create one of these database before continuing", dbNames)
	}

	err = createPostgresDatabase(dbName, db)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create Postgres database")
	}

	log.Debugf("Connecting to database '%s', using connection string: '%s'", dbName, MakeDBCred(datasource))
	db, err = sqlx.Open("postgres", datasource)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to open database '%s' in Postgres server", dbName)
	}

	err = createPostgresTables(dbName, db)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create Postgres tables")
	}

	return &DB{db, false}, nil
}

func createPostgresDatabase(dbName string, db *sqlx.DB) error {
	log.Debugf("Creating Postgres Database (%s) if it does not exists...", dbName)

	query := "CREATE DATABASE " + dbName
	_, err := db.Exec(query)
	if err != nil {
		if !strings.Contains(err.Error(), fmt.Sprintf("database \"%s\" already exists", dbName)) {
			return errors.Wrap(err, "Failed to execute create database query")
		}
	}

	return nil
}

func createPostgresTables(dbName string, db *sqlx.DB) error {
	return nil
}

// Gets connection string without database
func getConnStr(datasource string, dbname string) string {
	re := regexp.MustCompile(`(dbname=)([^\s]+)`)
	connStr := re.ReplaceAllString(datasource, fmt.Sprintf("dbname=%s", dbname))
	return connStr
}

// getDBName gets database name from connection string
func getDBName(datasource string) string {
	var dbName string
	datasource = strings.ToLower(datasource)

	re := regexp.MustCompile(`(?:\/([^\/?]+))|(?:dbname=([^\s]+))`)
	getName := re.FindStringSubmatch(datasource)
	if getName != nil {
		dbName = getName[1]
		if dbName == "" {
			dbName = getName[2]
		}
	}

	return dbName
}

// MakeDBCred hides DB credential in connection string
func MakeDBCred(str string) string {
	matches := dbURLRegex.FindStringSubmatch(str)

	if len(matches) == 10 {
		matchIdxs := dbURLRegex.FindStringSubmatchIndex(str)
		substr := str[matchIdxs[0]:matchIdxs[1]]
		for idx := 1; idx < len(matches); idx++ {
			if matches[idx] != "" {
				if strings.Index(matches[idx], "user=") == 0 {
					substr = strings.Replace(substr, matches[idx], "user=****", 1)
				} else if strings.Index(matches[idx], "password=") == 0 {
					substr = strings.Replace(substr, matches[idx], "password=****", 1)
				} else {
					substr = strings.Replace(substr, matches[idx], "****", 1)
				}
			}
		}
		str = str[:matchIdxs[0]] + substr + str[matchIdxs[1]:len(str)]
	}
	return str
}
