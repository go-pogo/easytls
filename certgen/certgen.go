// Copyright (c) 2022, Roel Schut. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package certgen

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/go-pogo/easytls"
	"github.com/go-pogo/errors"
	"io"
	"math/big"
	"time"
)

type PrivateKey interface {
	crypto.PrivateKey
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
}

type PrivateKeySigner interface {
	PrivateKey
	crypto.Signer
}

type Certificate interface {
	easytls.TLSCertificateLoader
	easytls.X509CertificateLoader
	PrivateKey() PrivateKeySigner
}

type CertificateGenerator interface {
	Generate(parent Certificate, template *x509.Certificate) (Certificate, error)
}

var limit = new(big.Int).Lsh(big.NewInt(1), 128)

func SerialNumber(randReader io.Reader) (*big.Int, error) {
	if randReader == nil {
		randReader = rand.Reader
	}

	n, err := rand.Int(randReader, limit)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return n, nil
}

const rsaDefaultBits = 2048

var defaultKeyGenerator = rsaKeyGen(rsaDefaultBits)

func GenerateKey(r io.Reader) (PrivateKeySigner, error) {
	return defaultKeyGenerator(r)
}

var (
	_ CertificateGenerator = (*CertGen)(nil)
	_ easytls.Option       = (*CertGen)(nil)
)

type CertGen struct {
	Template     x509.Certificate
	RandReader   io.Reader
	SerialNumber func(io.Reader) (*big.Int, error)
	GenerateKey  func(io.Reader) (PrivateKeySigner, error)
}

func New(opts ...Option) (*CertGen, error) {
	var cg CertGen
	if err := cg.With(opts...); err != nil {
		return nil, err
	}
	if cg.RandReader == nil {
		cg.RandReader = rand.Reader
	}
	if cg.SerialNumber == nil {
		cg.SerialNumber = SerialNumber
	}
	if cg.GenerateKey == nil {
		_ = WithRSAKey(rsaDefaultBits)(&cg)
	}
	return &cg, nil
}

func (cg *CertGen) With(opts ...Option) error {
	var err error
	for _, opt := range opts {
		err = errors.Append(err, opt(cg))
	}
	return err
}

func (cg *CertGen) randReader() io.Reader {
	if cg.RandReader != nil {
		return cg.RandReader
	}
	return rand.Reader
}

func (cg *CertGen) serialNumber() (*big.Int, error) {
	if cg.SerialNumber != nil {
		return cg.SerialNumber(cg.randReader())
	}
	return SerialNumber(cg.randReader())
}

func (cg *CertGen) generateKey() (PrivateKeySigner, error) {
	if cg.GenerateKey != nil {
		return cg.GenerateKey(cg.randReader())
	}
	return GenerateKey(cg.randReader())
}

func (cg *CertGen) prepTemplate(templ *x509.Certificate) error {
	if templ.SerialNumber == nil {
		var err error
		templ.SerialNumber, err = cg.serialNumber()
		if err != nil {
			return err
		}
	}

	templ.KeyUsage |= x509.KeyUsageDigitalSignature

	// no GenerateKey means default GenerateKey which is RSA
	if cg.GenerateKey == nil {
		templ.KeyUsage |= x509.KeyUsageKeyEncipherment
	}

	if templ.NotBefore.IsZero() {
		if !cg.Template.NotBefore.IsZero() {
			templ.NotBefore = cg.Template.NotBefore
		} else {
			templ.NotBefore = time.Now()
		}
	}
	if templ.NotAfter.IsZero() {
		templ.NotAfter = cg.Template.NotAfter
	}

	copyMissingSubjectFields(cg.Template.Subject, &templ.Subject)
	return nil
}

const panicNilTemplate = "certgen.Generate: template should not be nil"

// Generate new [Certificate] based on the provided [x509.Certificate] template
// and optional parent [Certificate], using [x509.CreateCertificate]. When
// parent is nil, the generated certificate will be self-signed.
func (cg *CertGen) Generate(parent Certificate, template *x509.Certificate) (Certificate, error) {
	if template == nil {
		panic(panicNilTemplate)
	}

	key, err := cg.generateKey()
	if err != nil {
		return nil, err
	}
	if err = cg.prepTemplate(template); err != nil {
		return nil, err
	}

	if parent == nil {
		if cg.GenerateKey == nil {
			template.KeyUsage |= x509.KeyUsageKeyEncipherment
		}
		if template.NotAfter.IsZero() {
			template.NotAfter = template.NotBefore.AddDate(1, 0, 0) // 1 year
		}
		if len(template.Subject.Organization) == 0 {
			template.Subject.Organization = []string{"self-signed"}
		}

		// create self-signed certificate
		der, err := x509.CreateCertificate(cg.randReader(), template, template, key.Public(), key)
		if err != nil {
			return nil, err
		}
		return newCertificate(template, der, key), nil
	}

	p, err := parent.LoadX509Certificate()
	if err != nil {
		return nil, err
	}

	if template.NotAfter.IsZero() {
		template.NotAfter = template.NotBefore.AddDate(10, 0, 0) // 10 years
	}

	// create certificate signed by parent
	der, err := x509.CreateCertificate(cg.randReader(), template, p, key.Public(), parent.PrivateKey())
	if err != nil {
		return nil, err
	}

	return newCertificate(template, der, key), nil
}

func (cg *CertGen) ApplyTo(conf *tls.Config, target easytls.Target) error {
	var template *x509.Certificate
	switch target {
	case easytls.TargetServer:
		template = easytls.ServerCertificate("localhost")

	case easytls.TargetClient:
		template = easytls.ClientCertificate()

	default:
		return errors.WithStack(&easytls.InvalidTarget{Target: target})
	}

	cert, err := cg.Generate(nil, template)
	if err != nil {
		return err
	}

	conf.Certificates, err = easytls.LoadAndAppend(conf.Certificates, cert)
	return err
}

var _ Certificate = (*certificate)(nil)

type certificate struct {
	cert *x509.Certificate
	key  PrivateKeySigner
	der  []byte
}

func newCertificate(cert *x509.Certificate, der []byte, key PrivateKeySigner) *certificate {
	return &certificate{cert: cert, der: der, key: key}
}

func (c *certificate) PrivateKey() PrivateKeySigner { return c.key }

func (c *certificate) LoadTLSCertificate() (*tls.Certificate, error) {
	var cert tls.Certificate
	cert.Certificate = append(cert.Certificate, c.der)
	cert.PrivateKey = c.key
	return &cert, nil
}

func (c *certificate) LoadX509Certificate() (*x509.Certificate, error) {
	cert := *c.cert // shallow copy
	return &cert, nil
}

func copyMissingSubjectFields(src pkix.Name, dest *pkix.Name) {
	if len(dest.Country) == 0 {
		dest.Country = src.Country
	}
	if len(dest.Organization) == 0 {
		dest.Organization = src.Organization
	}
	if len(dest.OrganizationalUnit) == 0 {
		dest.OrganizationalUnit = src.OrganizationalUnit
	}
	if len(dest.Locality) == 0 {
		dest.Locality = src.Locality
	}
	if len(dest.Province) == 0 {
		dest.Province = src.Province
	}
	if len(dest.StreetAddress) == 0 {
		dest.StreetAddress = src.StreetAddress
	}
	if len(dest.PostalCode) == 0 {
		dest.PostalCode = src.PostalCode
	}
}
