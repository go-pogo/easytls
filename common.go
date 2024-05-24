// Copyright (c) 2022, Roel Schut. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package easytls

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/go-pogo/errors"
	"net"
	"time"
)

// DefaultTLSConfig returns a modern preconfigured [tls.Config].
func DefaultTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,

		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}
}

// GetCertificate can be used in [tls.Config] to load a certificate when it's
// requested for.
func GetCertificate(cl TLSCertificateLoader) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := cl.LoadTLSCertificate()
		if err != nil {
			return nil, errors.WithStack(err)
		}
		return cert, nil
	}
}

// CACertificate returns a basic CA [x509.Certificate] with a validity of 10
// years.
func CACertificate(subj pkix.Name) *x509.Certificate {
	var cert x509.Certificate
	cert.BasicConstraintsValid = true
	cert.IsCA = true
	cert.KeyUsage |= x509.KeyUsageCertSign
	cert.KeyUsage |= x509.KeyUsageDigitalSignature
	cert.NotBefore = time.Now()
	cert.NotAfter = cert.NotBefore.AddDate(10, 0, 0)
	cert.Subject = subj
	return &cert
}

func ServerCertificate(hosts ...string) *x509.Certificate {
	var cert x509.Certificate
	cert.KeyUsage |= x509.KeyUsageDigitalSignature
	cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	cert.NotBefore = time.Now()
	cert.NotAfter = cert.NotBefore.AddDate(1, 0, 0)

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			cert.IPAddresses = append(cert.IPAddresses, ip)
		} else {
			cert.DNSNames = append(cert.DNSNames, h)
		}
	}

	return &cert
}

func ClientCertificate() *x509.Certificate {
	var cert x509.Certificate
	cert.KeyUsage |= x509.KeyUsageDigitalSignature
	cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	cert.NotBefore = time.Now()
	cert.NotAfter = cert.NotBefore.AddDate(1, 0, 0)
	return &cert
}

func CopyMissingSubjectFields(src pkix.Name, dest *pkix.Name) {
	if dest.Country == nil {
		dest.Country = src.Country
	}
	if dest.Organization == nil {
		dest.Organization = src.Organization
	}
	if dest.OrganizationalUnit == nil {
		dest.OrganizationalUnit = src.OrganizationalUnit
	}
	if dest.Locality == nil {
		dest.Locality = src.Locality
	}
	if dest.Province == nil {
		dest.Province = src.Province
	}
	if dest.StreetAddress == nil {
		dest.StreetAddress = src.StreetAddress
	}
	if dest.PostalCode == nil {
		dest.PostalCode = src.PostalCode
	}
	if dest.SerialNumber == "" {
		dest.SerialNumber = src.SerialNumber
	}
	if dest.CommonName == "" {
		dest.CommonName = src.CommonName
	}
	if dest.Names == nil {
		dest.Names = src.Names
	}
	if dest.ExtraNames == nil {
		dest.ExtraNames = src.ExtraNames
	}
}
