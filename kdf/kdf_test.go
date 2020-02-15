package kdf

import (
	"encoding/hex"
	"testing"
)

func TestSCrypt_Derive(t *testing.T) {
	derived, err := sCrypt{}.Derive(4, []byte("password"), []byte{1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4})
	if err != nil {
		t.Error(err)
	}
	if hex.EncodeToString(derived) != "1ac7b37b2173dcc95dd158c880e6de2caed7fcb0530ba86d343497b6cf6cd71f" {
		t.Fail()
	}
}

func TestBCrypt_Derive(t *testing.T) {
	derived, err := bCrypt{}.Derive(4, []byte("password"), []byte{1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4})
	if err != nil {
		t.Error(err)
	}
	if hex.EncodeToString(derived) != "f89795089a19a4f990a30ea1563cac4fa7e4655aea290219e88902a3125c351b" {
		t.Fail()
	}
}

func TestPbkdf2sha512_Derive(t *testing.T) {
	derived, err := pbkdf2sha512{}.Derive(4, []byte("password"), []byte{1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4})
	if err != nil {
		t.Error(err)
	}
	if hex.EncodeToString(derived) != "72bf7d2b4d1f18c97a333e3a89e7f22dc9771b968ddcbc1a494fbbf507059b13" {
		t.Fail()
	}
}
