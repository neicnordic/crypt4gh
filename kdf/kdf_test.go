package kdf

import (
	"encoding/hex"
	"testing"
)

func TestKDF(t *testing.T) {
	tests := []struct {
		name string
		hash string
	}{
		{
			name: "scrypt",
			hash: "1ac7b37b2173dcc95dd158c880e6de2caed7fcb0530ba86d343497b6cf6cd71f",
		},
		{
			name: "bcrypt",
			hash: "f89795089a19a4f990a30ea1563cac4fa7e4655aea290219e88902a3125c351b",
		},
		{
			name: "pbkdf2_hmac_sha256",
			hash: "72bf7d2b4d1f18c97a333e3a89e7f22dc9771b968ddcbc1a494fbbf507059b13",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			derived, err := KDFS[test.name].Derive(4, []byte("password"), []byte{1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4})
			if err != nil {
				t.Error(err)
			}
			if hex.EncodeToString(derived) != test.hash {
				t.Fail()
			}
		})
	}
}
