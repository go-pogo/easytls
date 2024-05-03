// Copyright (c) 2023, Roel Schut. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package easytls

import (
	"crypto/tls"
	"crypto/x509"
)

// An Option can be applied to a [tls.Config].
type Option interface {
	ApplyTo(conf *tls.Config, target Target) error
}

type optionFunc func(*tls.Config, Target) error

func (fn optionFunc) ApplyTo(conf *tls.Config, target Target) error {
	return fn(conf, target)
}

func WithTLSRootCAs(certs ...tls.Certificate) Option {
	return optionFunc(func(conf *tls.Config, target Target) error {
		if conf == nil || len(certs) == 0 {
			return nil
		}

		pool := getCertPool(conf, target)
		for _, cert := range certs {
			x, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				return err
			}
			pool.AddCert(x)
		}
		return nil
	})
}

func getCertPool(conf *tls.Config, target Target) *x509.CertPool {
	if target == TargetServer {
		if conf.ClientCAs == nil {
			conf.ClientCAs = x509.NewCertPool()
		}
		return conf.ClientCAs
	}
	if target == TargetClient {
		if conf.RootCAs == nil {
			conf.RootCAs = x509.NewCertPool()
		}
		return conf.RootCAs
	}
	return nil
}
