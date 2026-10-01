// Package config loads the issuer and role-to-permission mapping file.
package config

import (
	"errors"
	"fmt"
	"os"

	"go.yaml.in/yaml/v3"
)

// GlobalAccount is the implicit account of users defined in static NATS config.
const GlobalAccount = "$G"

// Config is the content of the permissions file (usually a mounted ConfigMap).
type Config struct {
	Issuers        []Issuer        `yaml:"issuers"`
	DefaultAccount string          `yaml:"defaultAccount"`
	Roles          map[string]Role `yaml:"roles"`
}

// Issuer is a trusted OIDC issuer, e.g. one Keycloak realm.
type Issuer struct {
	// URL must equal the "iss" claim of the tokens.
	URL string `yaml:"url"`
	// DiscoveryURL overrides where discovery is fetched from (e.g. in-cluster service).
	DiscoveryURL string `yaml:"discoveryURL"`
	Audience     string `yaml:"audience"`
	// RoleClient selects resource_access.<client>.roles; empty uses realm roles only.
	RoleClient string `yaml:"roleClient"`
}

// Role maps one Keycloak role to NATS permissions.
type Role struct {
	Account string     `yaml:"account"`
	Pub     Permission `yaml:"pub"`
	Sub     Permission `yaml:"sub"`
	Resp    *Response  `yaml:"resp"`
}

// Permission is an allow/deny subject list.
type Permission struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

// Response allows replying to received requests without explicit publish permissions.
type Response struct {
	MaxMsgs int    `yaml:"maxMsgs"`
	TTL     string `yaml:"ttl"`
}

// Load reads and validates a permissions file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- path is operator supplied
	if err != nil {
		return nil, fmt.Errorf("read permissions file: %w", err)
	}
	return Parse(b)
}

// Parse decodes and validates permissions file content.
func Parse(b []byte) (*Config, error) {
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse permissions file: %w", err)
	}
	if c.DefaultAccount == "" {
		c.DefaultAccount = GlobalAccount
	}
	return &c, c.Validate()
}

// Validate checks the config for missing mandatory fields.
func (c *Config) Validate() error {
	var errs []error
	if len(c.Issuers) == 0 {
		errs = append(errs, errors.New("at least one issuer required"))
	}
	for i, is := range c.Issuers {
		if is.URL == "" {
			errs = append(errs, fmt.Errorf("issuers[%d]: url required", i))
		}
		if is.Audience == "" {
			errs = append(errs, fmt.Errorf("issuers[%d]: audience required", i))
		}
	}
	if len(c.Roles) == 0 {
		errs = append(errs, errors.New("at least one role required"))
	}
	return errors.Join(errs...)
}

// AccountFor returns the role account or the default account.
func (c *Config) AccountFor(r Role) string {
	if r.Account != "" {
		return r.Account
	}
	return c.DefaultAccount
}
