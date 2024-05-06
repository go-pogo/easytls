// Copyright (c) 2022, Roel Schut. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package easytls

import (
	"crypto/tls"
	"github.com/go-pogo/errors"
	"strconv"
)

type Target uint8

const (
	TargetServer Target = iota
	TargetClient

	CACertError errors.Kind = "ca certificate error"
)

type InvalidTarget struct {
	Target Target
}

func (e InvalidTarget) Error() string {
	return "invalid target " + strconv.FormatUint(uint64(e.Target), 10)
}

var _ Option = (*Config)(nil)

// Config is a general config struct which can be used to configure or create
// a [tls.Config] for clients or servers.
type Config struct {
	// CACertFile is the path to the root certificate authority file. It is
	// used to verify the client's (whom connect to the server) certificate.
	CACertFile CertificateFile `env:"" flag:"tls-ca"`
	// CertFile is the path to the server's certificate file.
	CertFile string `env:"" flag:"tls-cert"`
	// KeyFile is the path to the server's private key file.
	KeyFile string `env:"" flag:"tls-key"`

	// VerifyClient enables mutual tls authentication.
	VerifyClient bool `env:""`
	// InsecureSkipVerify disabled all certificate verification and should only
	// be used for testing. See [tls.Config.InsecureSkipVerify] for additional
	// information.
	InsecureSkipVerify bool `env:""`
}

// Client creates a [tls.Config] for client connections. It is based on
// [DefaultTLSConfig], with [Config] applied to it.
func (tc Config) Client() (*tls.Config, error) {
	conf := DefaultTLSConfig()
	return conf, tc.ApplyTo(conf, TargetClient)
}

// Server creates a [tls.Config] for server connections. It is based on
// [DefaultTLSConfig], with [Config] applied to it.
func (tc Config) Server() (*tls.Config, error) {
	conf := DefaultTLSConfig()
	return conf, tc.ApplyTo(conf, TargetServer)
}

// ApplyTo applies the [Config] fields' values to the provided [tls.Config].
func (tc Config) ApplyTo(conf *tls.Config, target Target) error {
	if conf == nil {
		return nil
	}

	if tc.CACertFile != "" {
		pool, err := getCertPool(conf, target)
		if err != nil {
			return err
		}
		if err = LoadAndAdd(pool, tc.CACertFile); err != nil {
			return errors.WithKind(err, CACertError)
		}
	}

	conf.InsecureSkipVerify = tc.InsecureSkipVerify
	if tc.VerifyClient {
		conf.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return KeyPair{
		CertFile: tc.CertFile,
		KeyFile:  tc.KeyFile,
	}.ApplyTo(conf, target)
}

// DefaultTLSConfig returns a modern preconfigured [tls.Config].
func DefaultTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,

		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},

		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
}
