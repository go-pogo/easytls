// Copyright (c) 2024, Roel Schut. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package certgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"github.com/go-pogo/errors"
	"io"
	"time"
)

const (
	RSAKeyGeneratorError   errors.Kind = "error generating RSA key"
	ECDSAKeyGeneratorError errors.Kind = "error generating ECDSA key"
)

type Option func(cg *CertGen) error

func WithRSAKey(rsaBits int) Option {
	return func(cg *CertGen) error {
		cg.Template.KeyUsage |= x509.KeyUsageKeyEncipherment
		cg.GenerateKey = rsaKeyGen(rsaBits)
		return nil
	}
}

func rsaKeyGen(bits int) func(r io.Reader) (PrivateKeySigner, error) {
	return func(r io.Reader) (PrivateKeySigner, error) {
		pk, err := rsa.GenerateKey(r, bits)
		if err != nil {
			return nil, errors.WithKind(err, RSAKeyGeneratorError)
		}
		return pk, nil
	}
}

type UnsupportedEllipticCurveError struct {
	Curve string
}

func (err UnsupportedEllipticCurveError) Error() string {
	return "unsupported elliptic curve " + err.Curve
}

func WithECDSAKey(ecdsaCurve string) Option {
	return func(cg *CertGen) error {
		var curve elliptic.Curve

		switch ecdsaCurve {
		case "P224":
			curve = elliptic.P224()
		case "P256", "":
			curve = elliptic.P256()
		case "P384":
			curve = elliptic.P384()
		case "P521":
			curve = elliptic.P521()
		default:
			return errors.WithStack(&UnsupportedEllipticCurveError{ecdsaCurve})
		}

		cg.GenerateKey = func(r io.Reader) (PrivateKeySigner, error) {
			pk, err := ecdsa.GenerateKey(curve, r)
			if err != nil {
				return nil, errors.WithKind(err, ECDSAKeyGeneratorError)
			}
			return pk, nil
		}
		return nil
	}
}

func WithNotBefore(t time.Time) Option {
	return func(gen *CertGen) error {
		gen.Template.NotBefore = t
		return nil
	}
}

func WithNotAfter(t time.Time) Option {
	return func(gen *CertGen) error {
		gen.Template.NotAfter = t
		return nil
	}
}
