// Copyright (c) 2023, Roel Schut. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package easytls

import (
	"crypto/tls"

	"github.com/go-pogo/errors"
)

var (
	_ TLSCertificateLoader = (*KeyPair)(nil)
	_ Option               = (*KeyPair)(nil)
)

// KeyPair contains the paths to PEM encoded certificate and key pair of files,
// which can be loaded using [KeyPair.LoadTLSCertificate].
type KeyPair struct {
	CertFile string
	KeyFile  string
}

func (kp KeyPair) IsEmpty() bool {
	return kp.CertFile == "" && kp.KeyFile == ""
}

// LoadTLSCertificate reads and parses the key pair files with
// [tls.LoadX509KeyPair]. The files must contain valid PEM encoded data.
func (kp KeyPair) LoadTLSCertificate() (*tls.Certificate, error) {
	if kp.IsEmpty() {
		return nil, nil
	}

	c, err := tls.LoadX509KeyPair(kp.CertFile, kp.KeyFile)
	return &c, errors.Wrap(err, ErrLoadCertificate)
}

// ApplyTo adds the [KeyPair] certificate to the provided [tls.Config].
func (kp KeyPair) ApplyTo(conf *tls.Config, target Target) error {
	if conf == nil || kp.IsEmpty() {
		return nil
	}
	if conf.GetCertificate == nil && target == TargetServer {
		conf.GetCertificate = GetCertificate(kp)
		return nil
	}

	var err error
	conf.Certificates, err = loadAndAppend(conf.Certificates, kp)
	return err
}

var (
	_ TLSCertificateLoader = (*PEMBlocks)(nil)
	_ Option               = (*PEMBlocks)(nil)
)

// PEMBlocks contains PEM encoded certificate and key data which can be loaded
// using [KeyPair.LoadTLSCertificate].
type PEMBlocks struct {
	Cert []byte
	Key  []byte
}

func (pb PEMBlocks) IsEmpty() bool {
	return len(pb.Cert) == 0 && len(pb.Key) == 0
}

// LoadTLSCertificate parses the [PEMBlocks.Cert] and [PEMBlocks.Key] blocks
// using [tls.X509KeyPair]. The []byte values must contain valid PEM encoded
// data.
func (pb PEMBlocks) LoadTLSCertificate() (*tls.Certificate, error) {
	if pb.IsEmpty() {
		return nil, nil
	}

	c, err := tls.X509KeyPair(pb.Cert, pb.Key)
	return &c, errors.Wrap(err, ErrLoadCertificate)
}

// ApplyTo adds the [PEMBlocks] certificates to the provided [tls.Config].
func (pb PEMBlocks) ApplyTo(conf *tls.Config, _ Target) error {
	if conf == nil {
		return nil
	}

	var err error
	conf.Certificates, err = loadAndAppend(conf.Certificates, pb)
	return err
}
