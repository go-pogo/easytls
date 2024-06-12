// Copyright (c) 2022, Roel Schut. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package easytls

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/go-pogo/errors"
	"strconv"
)

type Target uint8

const (
	TargetServer Target = iota + 1
	TargetClient

	ErrAddCACertToPool errors.Msg = "failed to add CA certificate to pool"
	ErrNotMarkedAsCA   errors.Msg = "certificate is not marked as a CA"
	ErrMissingCertSign errors.Msg = "certificate is missing the cert sign flag"
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
	// CACertFile is the path to the root certificate authority (CA) file. It
	// is used to verify both client and server certificates are signed by the
	// same CA.
	CACertFile CertificateFile `env:""`
	// CertFile is the path to the certificate file.
	CertFile string `env:""`
	// KeyFile is the path to the private key file.
	KeyFile string `env:""`
	// VerifyClient enables mutual TLS authentication.
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

// ApplyTo applies the [Config] fields' values to the provided [tls.Config] for
// the specified [Target].
func (tc Config) ApplyTo(conf *tls.Config, target Target) error {
	if conf == nil {
		return nil
	}

	conf.InsecureSkipVerify = tc.InsecureSkipVerify

	if tc.CACertFile != "" {
		cert, err := tc.CACertFile.LoadX509Certificate()
		if err != nil {
			return errors.Wrap(err, ErrAddCACertToPool)
		}
		if valid, err := ValidateCA(cert); err != nil {
			return errors.Wrap(err, ErrAddCACertToPool)
		} else if valid {
			pool, err := getCertPool(conf, target)
			if err != nil {
				return err
			}
			pool.AddCert(cert)
		}
	}

	if tc.VerifyClient {
		if conf.InsecureSkipVerify {
			conf.ClientAuth = tls.RequireAnyClientCert
		} else {
			conf.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}

	kp := KeyPair{CertFile: tc.CertFile, KeyFile: tc.KeyFile}
	if err := kp.ApplyTo(conf, target); err != nil {
		return err
	}
	return nil
}

// ValidateCA checks if the provided [x509.Certificate] can be used as CA
// certificate. It return true when the certificate is valid, otherwise false.
// Any reasons why the certificate is invalid will be returned as an error, or
// nil when no non-nil certificate is provided.
func ValidateCA(cert *x509.Certificate) (bool, error) {
	if cert == nil {
		return false, nil
	}

	var err error
	if !cert.IsCA {
		err = errors.New(ErrNotMarkedAsCA)
	}
	if cert.KeyUsage == 0 || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		err = errors.Append(err, errors.New(ErrMissingCertSign))
	}
	return err == nil, err
}

func getCertPool(conf *tls.Config, target Target) (*x509.CertPool, error) {
	switch target {
	case TargetServer:
		if conf.ClientCAs == nil {
			conf.ClientCAs = x509.NewCertPool()
		}
		return conf.ClientCAs, nil

	case TargetClient:
		if conf.RootCAs == nil {
			conf.RootCAs = x509.NewCertPool()
		}
		return conf.RootCAs, nil

	default:
		return nil, errors.WithStack(&InvalidTarget{Target: target})
	}
}
