package util_test

import (
	"testing"
	"time"

	"github.com/rkcloudchain/rksync-ca/util"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

type S struct {
	Dur        time.Duration     `help:"Duration"`
	Slice      []string          `help:"Slice description"`
	Str        string            `def:"defval" help:"Str1 description"`
	Int        int               `def:"10" help:"Int1 description"`
	T          T                 `help:"T description"`
	IntArray   []int             `help:"Int array description"`
	Map        map[string]string `skip:"true"`
	TPrt       *T                `help:"T PTR description"`
	Interface  interface{}       `skip:"true"`
	unExported string
}

type T struct {
	Str  string `help:"Str2 description"`
	Int  int    `skip:"true"`
	RPtr *R
}

type R struct {
	Bool bool   `def:"true" help:"Bool description"`
	Str  string `help:"Str3 description"`
}

func TestRegisterFlags(t *testing.T) {
	tags := map[string]string{
		"help.t.int": "This is an int field",
	}
	err := util.RegisterFlags(viper.GetViper(), &pflag.FlagSet{}, &S{}, tags)
	assert.NoError(t, err)
	err = util.RegisterFlags(viper.GetViper(), &pflag.FlagSet{}, &R{}, tags)
	assert.NoError(t, err)
}

func TestParseObj(t *testing.T) {
	err := util.ParseObject(&S{}, func(*util.Field) error { return nil }, nil)
	assert.NoError(t, err)
	err = util.ParseObject(&S{}, nil, nil)
	assert.Error(t, err)
}
