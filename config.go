// Copyright (c) 2022, Roel Schut. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package easytls

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/go-pogo/errors"
	"os"
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

type Config struct {
	// CACertFile is the path to the root certificate authority file. It is
	// used to verify the client's (whom connect to the server) certificate.
	CACertFile string `env:"" flag:"tls-ca"`
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

func (tc Config) Client() (*tls.Config, error) {
	conf := DefaultTLSConfig()
	return conf, tc.ApplyTo(conf, TargetClient)
}

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
		data, err := os.ReadFile(tc.CACertFile)
		if err != nil {
			return errors.WithKind(err, CACertError)
		}
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			return errors.WithKind(err, CACertError)
		}

		pool := getCertPool(conf, target)
		if pool == nil {
			return errors.WithStack(&InvalidTarget{Target: target})
		}
		pool.AddCert(cert)
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
