package auth

import (
	"errors"
	"strings"
)

type Credentials struct {
	AccessKey string
	SecretKey string
}

func ParseXAPIKey(h string) (Credentials, error) {
	if strings.TrimSpace(h) == "" {
		return Credentials{}, errors.New("missing x-apikey header")
	}

	parts := strings.Split(h, ";")
	vals := map[string]string{}
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(kv[0]))
		v := strings.TrimSpace(kv[1])
		vals[k] = v
	}

	creds := Credentials{
		AccessKey: vals["accesskey"],
		SecretKey: vals["secretkey"],
	}
	if creds.AccessKey == "" || creds.SecretKey == "" {
		return Credentials{}, errors.New("x-apikey must include accesskey and secretkey")
	}
	return creds, nil
}

func IsAllowed(accessKey string, allowed []string) bool {
	for _, key := range allowed {
		if accessKey == key {
			return true
		}
	}
	return false
}
