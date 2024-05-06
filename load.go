// Copyright (c) 2023, Roel Schut. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package easytls

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/go-pogo/errors"
)

const (
	LoadCertificateError = "failed to load certificate"
)

// TLSCertificateLoader loads a [tls.Certificate] from any source.
type TLSCertificateLoader interface {
	LoadTLSCertificate() (*tls.Certificate, error)
}

// LoadAndAppend loads the certificates from the provided
// [TLSCertificateLoader]s and appends them to the provided [tls.Certificate]
// slice.
// Errors that occur are grouped together and returned as a single error after
// all certificates have been loaded.
func LoadAndAppend(list []tls.Certificate, certs ...TLSCertificateLoader) ([]tls.Certificate, error) {
	var err error
	for _, c := range certs {
		if c == nil {
			continue
		}

		var loadErr error
		if list, loadErr = loadAndAppend(list, c); loadErr != nil {
			err = errors.Append(err, loadErr)
			continue
		}
	}
	return list, err
}

func loadAndAppend(list []tls.Certificate, c TLSCertificateLoader) ([]tls.Certificate, error) {
	if cert, err := c.LoadTLSCertificate(); err != nil {
		return list, errors.WithStack(err)
	} else if cert != nil {
		list = append(list, *cert)
	}
	return list, nil
}

// X509CertificateLoader loads a [x509.Certificate] from any source.
type X509CertificateLoader interface {
	LoadX509Certificate() (*x509.Certificate, error)
}

// LoadAndAdd loads the certificates from the provided [X509CertificateLoader]s
// and adds them to the provided [x509.CertPool].
// Errors that occur are grouped together and returned as a single error after
// all certificates have been loaded.
func LoadAndAdd(pool *x509.CertPool, certs ...X509CertificateLoader) error {
	var err error
	for _, cert := range certs {
		c, loadErr := cert.LoadX509Certificate()
		if loadErr != nil {
			err = errors.Append(err, loadErr)
			continue
		}
		pool.AddCert(c)
	}
	return err
}

func LoadAndAddSystem(certs ...X509CertificateLoader) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return pool, LoadAndAdd(pool, certs...)
}
