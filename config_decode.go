package netflowexporter

import (
	"reflect"
	"strings"
	"time"

	"go.opentelemetry.io/collector/confmap"
)

// Unmarshal rejects unknown keys and scalar coercion before confmap's weak
// numeric conversions can truncate a value. Errors never include raw input.
func (c *Config) Unmarshal(conf *confmap.Conf) error {
	if conf == nil || c == nil {
		return configError()
	}
	raw := conf.ToStringMap()
	if !strictConfigValue(raw, reflect.TypeFor[Config]()) {
		return configError()
	}
	// A different type avoids recursive calls to this method while preserving
	// caller-supplied defaults and Collector's duration decoder.
	type plain Config
	if err := conf.Unmarshal((*plain)(c)); err != nil {
		return configError()
	}
	if value, exists := raw["path_mtu"]; exists && value == nil {
		c.PathMTU = nil
	}
	if ipfix, ok := raw["ipfix"].(map[string]any); ok {
		if value, exists := ipfix["template_refresh_data_packets"]; exists && value == nil {
			c.IPFIX.TemplateRefreshDataPackets = nil
		}
	}
	return nil
}

func strictConfigValue(raw any, typ reflect.Type) bool {
	if typ.Kind() == reflect.Pointer {
		return raw != nil && strictConfigValue(raw, typ.Elem())
	}
	if raw == nil {
		return false
	}
	if typ == reflect.TypeFor[time.Duration]() {
		_, ok := raw.(string)
		return ok
	}
	v := reflect.ValueOf(raw)
	switch typ.Kind() {
	case reflect.Struct:
		values, ok := raw.(map[string]any)
		if !ok {
			return false
		}
		if typ == reflect.TypeFor[ProtocolIdentifier]() {
			if _, exists := values["number"]; !exists {
				return false // hopopt:0 also requires an explicit numeric member
			}
		}
		for key, value := range values {
			// Only these two documented optional controls allow explicit null.
			if value == nil && ((typ == reflect.TypeFor[Config]() && key == "path_mtu") ||
				(typ == reflect.TypeFor[IPFIXConfig]() && key == "template_refresh_data_packets")) {
				continue
			}
			found := false
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				if strings.Split(field.Tag.Get("mapstructure"), ",")[0] == key {
					if !strictConfigValue(value, field.Type) {
						return false
					}
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	case reflect.Slice:
		if v.Kind() != reflect.Slice {
			return false
		}
		for i := 0; i < v.Len(); i++ {
			if !strictConfigValue(v.Index(i).Interface(), typ.Elem()) {
				return false
			}
		}
		return true
	case reflect.String:
		return v.Kind() == reflect.String
	case reflect.Bool:
		return v.Kind() == reflect.Bool
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		var n uint64
		switch v.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			if v.Int() < 0 {
				return false
			}
			n = uint64(v.Int())
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			n = v.Uint()
		default:
			return false
		}
		return !reflect.New(typ).Elem().OverflowUint(n)
	default:
		return false
	}
}
