// Copyright (c) 2024, Roel Schut. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package easytls

import (
	"crypto/x509"
	"github.com/go-pogo/errors"
	"os"
)

var _ X509CertificateLoader = (*CertificateFile)(nil)

// CertificateFile contains the path to an existing certificate file which can
// be loaded using [CertificateFile.LoadX509Certificate].
type CertificateFile string

func (cf CertificateFile) String() string { return string(cf) }

func (cf CertificateFile) GoString() string { return `easytls.CertificateFile("` + string(cf) + `")` }

func (cf CertificateFile) LoadX509Certificate() (*x509.Certificate, error) {
	data, err := os.ReadFile(cf.String())
	if err != nil {
		return nil, errors.WithKind(err, LoadCertificateError)
	}

	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, errors.WithKind(err, LoadCertificateError)
	}
	return cert, nil
}
