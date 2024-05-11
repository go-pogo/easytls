// Copyright (c) 2023, Roel Schut. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package easytls

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/go-pogo/errors"
)

// An Option can be applied to a [tls.Config].
type Option interface {
	ApplyTo(conf *tls.Config, target Target) error
}

type optionFunc func(*tls.Config, Target) error

func (fn optionFunc) ApplyTo(conf *tls.Config, target Target) error {
	return fn(conf, target)
}

func Apply(conf *tls.Config, target Target, opts ...Option) error {
	var err error
	for _, opt := range opts {
		err = errors.Append(err, opt.ApplyTo(conf, target))
	}
	return err
}

func withRootCAs(fn func(pool *x509.CertPool) error) Option {
	return optionFunc(func(conf *tls.Config, target Target) error {
		if conf == nil {
			return nil
		}

		pool, err := getCertPool(conf, target)
		if err != nil {
			return err
		}

		return fn(pool)
	})
}

func WithTLSRootCAs(certs ...tls.Certificate) Option {
	return withRootCAs(func(pool *x509.CertPool) error {
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

func WithX509RootCAs(certs ...*x509.Certificate) Option {
	return withRootCAs(func(pool *x509.CertPool) error {
		for _, cert := range certs {
			pool.AddCert(cert)
		}
		return nil
	})
}

func WithLoadX509RootCAs(certs ...X509CertificateLoader) Option {
	return withRootCAs(func(pool *x509.CertPool) error {
		for _, cert := range certs {
			if cert == nil {
				continue
			}

			x, err := cert.LoadX509Certificate()
			if err != nil {
				return err
			}
			pool.AddCert(x)
		}
		return nil
	})
}
