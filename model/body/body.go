package body

type Segment struct {
}

type ChaCha20IETFPoly1305Segment struct {
	Segment
	nonce         [12]byte
	encryptedData []byte
	mac           [16]byte
}
