package util

import (
	"fmt"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// FlagString sets up a flag for a string, binding it to its name
func FlagString(v *viper.Viper, flags *pflag.FlagSet, name, short string, def string, desc string) {
	flags.StringP(name, short, def, desc)
	bindFlag(v, flags, name)
}

// common binding function
func bindFlag(v *viper.Viper, flags *pflag.FlagSet, name string) {
	flag := flags.Lookup(name)
	if flag == nil {
		panic(fmt.Errorf("failed to lookup '%s'", name))
	}
	v.BindPFlag(name, flag)
}
