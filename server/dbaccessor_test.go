package server_test

import (
	"testing"

	"github.com/rkcloudchain/rksync-ca/api"
	"github.com/rkcloudchain/rksync-ca/api/registry"
	dbutil "github.com/rkcloudchain/rksync-ca/db"
	"github.com/rkcloudchain/rksync-ca/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMySQL(t *testing.T) {
	db, err := dbutil.NewUserRegistryMySQL("root:@tcp(localhost:3306)/rksync_ca?charset=utf8")
	require.NoError(t, err)
	defer db.Close()

	accessor := server.NewDBAccessor(db)
	testEverything(t, accessor)
}

func testEverything(t *testing.T, accessor *server.Accessor) {
	testInsertAndGetUser(t, accessor)
}

func testInsertAndGetUser(t *testing.T, accessor *server.Accessor) {
	t.Log("TestInsertAndGetUser")

	insert := &registry.UserInfo{
		Name: "testuser",
		Pass: "123456",
		Attributes: []api.Attribute{
			api.Attribute{
				Name:  "cr.EnrollmentID",
				Value: "testuser",
			},
			api.Attribute{
				Name:  "cr.IntermediateCA",
				Value: "true",
			},
		},
	}

	err := accessor.InsertUser(insert)
	assert.NoError(t, err)

	user, err := accessor.GetUser(insert.Name, nil)
	assert.NoError(t, err)
	assert.Equal(t, insert.Name, user.GetName())
}
