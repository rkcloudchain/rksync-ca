package util

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/pkg/errors"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	// TagDefault is the tag name for a default value of a field as recognized
	// by RegisterFlags.
	TagDefault = "def"
	// TagHelp is the tag name for a help message of a field as recognized
	// by RegisterFlags.
	TagHelp = "help"
	// TagOpt is the tag name for a one character option of a field as recognized
	// by RegisterFlags.  For example, a value of "d" reserves "-d" for the
	// command line argument.
	TagOpt = "opt"
	// TagSkip is the tag name which causes the field to be skipped by
	// RegisterFlags.
	TagSkip = "skip"
	// TagHide is the tag name which causes the field to be hidden
	TagHide = "hide"
)

type flagRegistrar struct {
	flags *pflag.FlagSet
	tags  map[string]string
	viper *viper.Viper
}

func (fr *flagRegistrar) Register(f *Field) (err error) {
	// Don't register non-leaf fields
	if !f.Leaf {
		return nil
	}
	// Don't register fields with no address
	if f.Addr == nil {
		return errors.Errorf("Field is not addressable: %s", f.Path)
	}

	skip := fr.getTag(f, TagSkip)
	if skip != "" {
		return nil
	}

	help := fr.getTag(f, TagHelp)
	opt := fr.getTag(f, TagOpt)
	def := fr.getTag(f, TagDefault)
	hide := fr.getHideBooleanTag(f)

	switch f.Kind {
	case reflect.String:
		if help == "" && !hide {
			return errors.Errorf("Field is missing a help tag: %s", f.Path)
		}
		fr.flags.StringVarP(f.Addr.(*string), f.Path, opt, def, help)
	case reflect.Int:
		if help == "" && !hide {
			return errors.Errorf("Field is missing a help tag: %s", f.Path)
		}
		var intDef int
		if def != "" {
			intDef, err = strconv.Atoi(def)
			if err != nil {
				return errors.Errorf("Invalid integer value in 'def' tag of %s field", f.Path)
			}
		}
		fr.flags.IntVarP(f.Addr.(*int), f.Path, opt, intDef, help)
	case reflect.Int64:
		if help == "" && !hide {
			return errors.Errorf("Field is missing a help tag: %s", f.Path)
		}
		d, ok := f.Addr.(*time.Duration)
		if ok {
			var intDef time.Duration
			if def != "" {
				intDef, err = time.ParseDuration(def)
				if err != nil {
					return errors.Errorf("Invalid duration value in 'def' tag of %s field", f.Path)
				}
			}
			fr.flags.DurationVarP(d, f.Path, opt, intDef, help)
		} else {
			var intDef int64
			if def != "" {
				intDef, err = strconv.ParseInt(def, 10, 64)
				if err != nil {
					return errors.Errorf("Invalid int64 value in 'def' tag of %s field", f.Path)
				}
			}
			fr.flags.Int64VarP(f.Addr.(*int64), f.Path, opt, intDef, help)
		}
	case reflect.Bool:
		if help == "" && !hide {
			return errors.Errorf("Field is missing a help tag: %s", f.Path)
		}
		var boolDef bool
		if def != "" {
			boolDef, err = strconv.ParseBool(def)
			if err != nil {
				return errors.Errorf("Invalid boolean value in 'def' tag of %s field", f.Path)
			}
		}
		fr.flags.BoolVarP(f.Addr.(*bool), f.Path, opt, boolDef, help)
	case reflect.Slice:
		if f.Type.Elem().Kind() == reflect.String {
			if help == "" && !hide {
				return errors.Errorf("Field is missing a help tag: %s", f.Path)
			}
			fr.flags.StringSliceVarP(f.Addr.(*[]string), f.Path, opt, nil, help)
		} else {
			return nil
		}
	default:
		log.Debugf("Not registering flag for '%s' because it is a currently unsupported type: %s\n", f.Path, f.Kind)
		return nil
	}

	if hide {
		fr.flags.MarkHidden(f.Path)
	}
	bindFlag(fr.viper, fr.flags, f.Path)
	return nil
}

func (fr *flagRegistrar) getTag(f *Field, tagName string) string {
	var key, value string
	key = fmt.Sprintf("%s.%s", tagName, f.Path)
	if fr.tags != nil {
		value = fr.tags[key]
	}
	if value == "" {
		value = f.Tag.Get(tagName)
	}
	return value
}

func (fr *flagRegistrar) getHideBooleanTag(f *Field) bool {
	boolValue, err := strconv.ParseBool(f.Hide)
	if err != nil {
		return false
	}
	return boolValue
}

// RegisterFlags registers flags for all fields in an arbitrary 'config' object.
// This method recognizes the following field tags:
// "def" - the default value of the field;
// "opt" - the optional one character short name to use on the command line;
// "help" - the help message to display on the command line;
// "skip" - to skip the field.
func RegisterFlags(v *viper.Viper, flags *pflag.FlagSet, config interface{}, tags map[string]string) error {
	fr := &flagRegistrar{flags: flags, tags: tags, viper: v}
	return ParseObject(config, fr.Register, tags)
}

// Field is a field of an arbitrary struct
type Field struct {
	Name  string
	Path  string
	Type  reflect.Type
	Kind  reflect.Kind
	Leaf  bool
	Depth int
	Tag   reflect.StructTag
	Value interface{}
	Addr  interface{}
	Hide  string
}

// ParseObject parses an object structure, calling back with field info for each field
func ParseObject(obj interface{}, cb func(*Field) error, tags map[string]string) error {
	if cb == nil {
		return errors.New("nil callback")
	}
	return parse(obj, cb, nil, tags)
}

func parse(ptr interface{}, cb func(*Field) error, parent *Field, tags map[string]string) error {
	v := reflect.ValueOf(ptr)
	err := parse2(v, cb, parent, tags)
	if err != nil {
		return err
	}
	return nil
}

func parse2(val reflect.Value, cb func(*Field) error, parent *Field, tags map[string]string) error {
	var path string
	var depth int
	v := val.Elem()
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		vf := v.Field(i)
		tf := t.Field(i)
		name := strings.ToLower(tf.Name)
		// skip unexported fields
		if tf.Name[0] == name[0] {
			continue
		}
		if parent != nil {
			path = fmt.Sprintf("%s.%s", parent.Path, name)
			depth = parent.Depth + 1
		} else {
			path = name
		}

		kind := vf.Kind()
		leaf := kind != reflect.Struct && kind != reflect.Ptr
		field := &Field{
			Name:  name,
			Path:  path,
			Type:  tf.Type,
			Kind:  kind,
			Leaf:  leaf,
			Depth: depth,
			Tag:   tf.Tag,
			Value: vf.Interface(),
			Addr:  vf.Addr().Interface(),
		}
		if parent == nil || parent.Hide == "" {
			getHideTag(field, tags)
		} else {
			field.Hide = parent.Hide
		}
		err := cb(field)
		if err != nil {
			return err
		}
		if kind == reflect.Ptr {
			if tf.Tag.Get(TagSkip) == "true" {
				continue
			}
			rf := reflect.New(vf.Type().Elem())
			err := parse2(rf, cb, field, tags)
			if err != nil {
				return err
			}
		} else if kind == reflect.Struct {
			if tf.Tag.Get(TagSkip) == "true" {
				continue
			}
			err := parse(field.Addr, cb, field, tags)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func getHideTag(f *Field, tags map[string]string) {
	var key, value string
	key = fmt.Sprintf("%s.%s", "hide", f.Path)
	if tags != nil {
		value = tags[key]
	}
	if value == "" {
		value = f.Tag.Get(TagHide)
	}
	f.Hide = value
}

// common binding function
func bindFlag(v *viper.Viper, flags *pflag.FlagSet, name string) {
	flag := flags.Lookup(name)
	if flag == nil {
		panic(errors.Errorf("failed to lookup '%s'", name))
	}
	v.BindPFlag(name, flag)
}
