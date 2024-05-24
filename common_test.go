// Copyright (c) 2024, Roel Schut. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package easytls

import (
	"crypto/x509/pkix"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCopyMissingSubjectFields(t *testing.T) {
	t.Run("nil dest", func(t *testing.T) {
		assert.PanicsWithValue(t, panicNilDestSubject, func() {
			CopyMissingSubjectFields(pkix.Name{}, nil)
		})
	})

	t.Run("copy", func(t *testing.T) {
		want := pkix.Name{
			Country:            []string{"NL"},
			Organization:       []string{"pogo"},
			OrganizationalUnit: []string{"easytls"},
			Locality:           []string{"Some place"},
			Province:           []string{"Somewhere"},
			StreetAddress:      []string{"Over the rainbow"},
			PostalCode:         []string{"1234AB"},
			SerialNumber:       "0987654321",
			CommonName:         "foobar",
		}

		var have pkix.Name
		CopyMissingSubjectFields(want, &have)
		assert.Equal(t, want, have)
	})

}
