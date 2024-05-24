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

const ErrNoCertificateInPEM errors.Msg = "failed to find \"CERTIFICATE\" PEM block in data"

var (
	_ flag.Value            = (*CertificateFile)(nil)
	_ X509CertificateLoader = (*CertificateFile)(nil)
)

// CertificateFile contains the path to an existing certificate file which can
// be loaded using [CertificateFile.LoadX509Certificate]. The contents of the
// file must contain valid PEM encoded data.
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

	data = decodePem(data)
	if data == nil {
		return nil, errors.WithKind(ErrNoCertificateInPEM, LoadCertificateError)
	}

	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, errors.WithKind(err, LoadCertificateError)
	}
	return cert, nil
}

func decodePem(data []byte) []byte {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			return block.Bytes
		}
	}
	return nil
}
