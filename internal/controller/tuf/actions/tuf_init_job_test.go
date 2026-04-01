package actions

import (
	"testing"

	"github.com/securesign/operator/api/v1alpha1"
)

func TestHasKey(t *testing.T) {
	tests := []struct {
		name     string
		keys     []v1alpha1.TufKey
		keyName  string
		expected bool
	}{
		{
			name:     "no keys",
			keys:     nil,
			keyName:  "tsa.certchain.pem",
			expected: false,
		},
		{
			name: "key not present",
			keys: []v1alpha1.TufKey{
				{Name: "rekor.pub"},
				{Name: "ctfe.pub"},
			},
			keyName:  "tsa.certchain.pem",
			expected: false,
		},
		{
			name: "TSA key present",
			keys: []v1alpha1.TufKey{
				{Name: "rekor.pub"},
				{Name: "tsa.certchain.pem"},
			},
			keyName:  "tsa.certchain.pem",
			expected: true,
		},
		{
			name: "Fulcio key present",
			keys: []v1alpha1.TufKey{
				{Name: "fulcio_v1.crt.pem"},
				{Name: "rekor.pub"},
			},
			keyName:  "fulcio_v1.crt.pem",
			expected: true,
		},
		{
			name: "Rekor key not present",
			keys: []v1alpha1.TufKey{
				{Name: "fulcio_v1.crt.pem"},
			},
			keyName:  "rekor.pub",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasKey(tt.keys, tt.keyName); got != tt.expected {
				t.Errorf("hasKey() = %v, want %v", got, tt.expected)
			}
		})
	}
}
