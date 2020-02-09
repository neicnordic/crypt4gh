package headers

type HeaderPacketType uint32

const (
	DataEncryptionParameters HeaderPacketType = iota
	DataEditList
)

type HeaderEncryptionMethod uint32

const (
	X25519ChaCha20IETFPoly1305 HeaderEncryptionMethod = iota
)

type DataEncryptionMethod uint32

const (
	ChaCha20IETFPoly1305 DataEncryptionMethod = iota
)

type Header struct {
	magicNumber       [8]byte
	version           uint32
	headerPacketCount uint32
	headerPackets     []EncryptedHeaderPacket
}

type HeaderPacket struct {
	packetLength           uint32
	headerEncryptionMethod HeaderEncryptionMethod
	encryptedPayload       []byte
}

type X25519ChaCha20IETFPoly1305HeaderPacket struct {
	HeaderPacket
	writerPublicKey [32]byte
	nonce           [12]byte
	mac             [16]byte
}

type EncryptedHeaderPacket struct {
	packetType HeaderPacketType
}

type DataEncryptionParametersEncryptedHeaderPacket struct {
	EncryptedHeaderPacket
	dataEncryptionMethod DataEncryptionMethod
}

type ChaCha20IETFPoly1305DataEncryptionParametersEncryptedHeaderPacket struct {
	DataEncryptionParametersEncryptedHeaderPacket
	dataKey [32]byte
}

type DataEditListEncryptedHeaderPacket struct {
	EncryptedHeaderPacket
	numberLengths uint32
	lengths       []uint64
}
