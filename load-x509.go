// Copyright (c) 2024, Roel Schut. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package easytls

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"github.com/go-pogo/errors"
	"os"
)

var (
	_ flag.Value            = (*CertificateFile)(nil)
	_ X509CertificateLoader = (*CertificateFile)(nil)
)

// CertificateFile contains the path to an existing certificate file which can
// be loaded using [CertificateFile.LoadX509Certificate].
type CertificateFile string

func (cf *CertificateFile) Set(s string) error {
	*cf = CertificateFile(s)
	return nil
}

func (cf CertificateFile) String() string { return string(cf) }

func (cf CertificateFile) GoString() string { return `easytls.CertificateFile("` + string(cf) + `")` }

func (cf CertificateFile) LoadX509Certificate() (*x509.Certificate, error) {
	data, err := os.ReadFile(cf.String())
	if err != nil {
		return nil, errors.WithKind(err, LoadCertificateError)
	}

	block, _ := pem.Decode(data)

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.WithKind(err, LoadCertificateError)
	}
	return cert, nil
}
