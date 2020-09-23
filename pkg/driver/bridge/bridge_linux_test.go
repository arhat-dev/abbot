package bridge

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDriver_Ensure(t *testing.T) {
	tests := []struct {
		name      string
		expectErr bool
		config    interface{}
	}{
		{
			name:      "Default Config Invalid No Name",
			expectErr: true,
			config:    NewConfig(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			d, err := NewDriver(test.config)
			assert.NoError(t, err)

			err = d.Ensure(false)
			if test.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
