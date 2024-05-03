// Copyright (c) 2023, Roel Schut. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package easytls

import (
	"crypto/tls"
	"github.com/go-pogo/errors"
)

const (
	LoadCertificateError = "failed to load certificate"
)

// CertificateLoader loads a [tls.Certificate] from any source.
type CertificateLoader interface {
	LoadCertificate() (*tls.Certificate, error)
}

// GetCertificate can be used in [tls.Config] to load a certificate when it's
// requested for.
func GetCertificate(cl CertificateLoader) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := cl.LoadCertificate()
		if err != nil {
			return nil, errors.WithStack(err)
		}
		return cert, nil
	}
}

var (
	_ CertificateLoader = (*KeyPair)(nil)
	_ Option            = (*KeyPair)(nil)
)

// KeyPair contains the paths to a public/private key pair of files.
type KeyPair struct {
	CertFile string
	KeyFile  string
}

// LoadCertificate reads and parses the key pair files with
// [tls.LoadX509KeyPair]. The files must contain PEM encoded data.
func (kp KeyPair) LoadCertificate() (*tls.Certificate, error) {
	if kp.CertFile == "" && kp.KeyFile == "" {
		return nil, nil
	}

	c, err := tls.LoadX509KeyPair(kp.CertFile, kp.KeyFile)
	return &c, errors.WithKind(err, LoadCertificateError)
}

// ApplyTo adds the [KeyPair] certificates to the provided [tls.Config].
func (kp KeyPair) ApplyTo(conf *tls.Config, target Target) error {
	if conf == nil {
		return nil
	}
	if conf.GetCertificate == nil && target == TargetServer {
		conf.GetCertificate = GetCertificate(kp)
		return nil
	}

	if c, err := kp.LoadCertificate(); err != nil {
		return err
	} else if c != nil {
		conf.Certificates = append(conf.Certificates, *c)
	}
	return nil
}

var (
	_ CertificateLoader = (*PemBlocks)(nil)
	_ Option            = (*PemBlocks)(nil)
)

// certPEMBlock, keyPEMBlock
type PemBlocks struct {
	Cert []byte
	Key  []byte
}

// LoadCertificate parses the [PemBlocks.Cert] and [PemBlocks.Key] blocks
// using [tls.X509KeyPair]. The []byte values must contain PEM encoded data.
func (pb PemBlocks) LoadCertificate() (*tls.Certificate, error) {
	if len(pb.Cert) == 0 && len(pb.Key) == 0 {
		return nil, nil
	}

	c, err := tls.X509KeyPair(pb.Cert, pb.Key)
	return &c, errors.WithKind(err, LoadCertificateError)
}

// ApplyTo adds the [PemBlocks] certificates to the provided [tls.Config].
func (pb PemBlocks) ApplyTo(conf *tls.Config, _ Target) error {
	if conf == nil {
		return nil
	}
	if c, err := pb.LoadCertificate(); err != nil {
		return err
	} else if c != nil {
		conf.Certificates = append(conf.Certificates, *c)
	}
	return nil
}
