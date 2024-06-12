// Copyright (c) 2024, Roel Schut. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package easytls

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_ApplyTo(t *testing.T) {
	t.Run("VerifyClient", func(t *testing.T) {
		var conf tls.Config
		require.NoError(t, Config{VerifyClient: true}.ApplyTo(&conf, 0))
		assert.Equal(t, tls.RequireAndVerifyClientCert, conf.ClientAuth)
	})
	t.Run("InsecureSkipVerify", func(t *testing.T) {
		var conf tls.Config
		require.NoError(t, Config{InsecureSkipVerify: true}.ApplyTo(&conf, 0))
		assert.True(t, conf.InsecureSkipVerify)
	})
}

func TestValidateCA(t *testing.T) {
	tests := map[string]struct {
		cert      *x509.Certificate
		wantValid bool
		wantErr   []error
	}{
		"nil": {},
		"not marked as ca": {
			cert: &x509.Certificate{
				KeyUsage: x509.KeyUsageCertSign,
			},
			wantErr: []error{ErrNotMarkedAsCA},
		},
		"missing cert sign": {
			cert: &x509.Certificate{
				IsCA: true,
			},
			wantErr: []error{ErrMissingCertSign},
		},

		"CACertificate": {
			cert:      CACertificate(pkix.Name{}),
			wantValid: true,
		},
		"ServerCertificate": {
			cert:      ServerCertificate("localhost"),
			wantValid: false,
			wantErr:   []error{ErrNotMarkedAsCA, ErrMissingCertSign},
		},
		"ClientCertificate": {
			cert:      ClientCertificate(),
			wantValid: false,
			wantErr:   []error{ErrNotMarkedAsCA, ErrMissingCertSign},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			haveValid, haveErr := ValidateCA(tc.cert)
			assert.Equal(t, tc.wantValid, haveValid)
			if tc.wantErr == nil {
				assert.NoError(t, haveErr)
			} else {
				for _, wantErr := range tc.wantErr {
					assert.ErrorIs(t, haveErr, wantErr)
				}
			}
		})
	}
}
