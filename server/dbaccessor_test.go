package server

import (
	"testing"

	"github.com/rkcloudchain/rksync-ca/api"
	"github.com/rkcloudchain/rksync-ca/api/registry"
	dbutil "github.com/rkcloudchain/rksync-ca/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMySQL(t *testing.T) {
	db, err := dbutil.NewUserRegistryMySQL("root:@tcp(localhost:3306)/rksync_ca?parseTime=true&charset=utf8")
	require.NoError(t, err)
	defer db.Close()

	accessor := NewDBAccessor(db)
	testEverything(t, accessor)
}

func testEverything(t *testing.T, accessor *Accessor) {
	testInsertAndGetUser(t, accessor)
	testDeleteUser(t, accessor)
	testUpdateUser(t, accessor)
}

func testInsertAndGetUser(t *testing.T, accessor *Accessor) {
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

	attr, err := user.GetAttribute("cr.EnrollmentID")
	assert.NoError(t, err)
	assert.Equal(t, insert.Name, attr.GetValue())
}

func testDeleteUser(t *testing.T, accessor *Accessor) {
	t.Log("TestDeleteUser")

	insert := &registry.UserInfo{
		Name:       "deleteuser",
		Pass:       "123456",
		Attributes: []api.Attribute{},
	}

	err := accessor.InsertUser(insert)
	assert.NoError(t, err)

	_, err = accessor.DeleteUser(insert.Name)
	assert.NoError(t, err)

	_, err = accessor.GetUser(insert.Name, nil)
	assert.Error(t, err)
}

func testUpdateUser(t *testing.T, accessor *Accessor) {
	t.Log("TestUpdateUser")

	insert := &registry.UserInfo{
		Name:       "updateuser",
		Pass:       "123456",
		Attributes: []api.Attribute{},
	}

	err := accessor.InsertUser(insert)
	assert.NoError(t, err)

	insert.Pass = "654321"

	err = accessor.UpdateUser(nil, true)
	assert.Error(t, err)

	err = accessor.UpdateUser(insert, true)
	assert.NoError(t, err)

	user, err := accessor.GetUser(insert.Name, nil)
	assert.NoError(t, err)

	err = user.Login(insert.Pass, -1)
	assert.NoError(t, err)
}
